#!/usr/bin/env python3
"""Build the syscall whitelist eBPF object from a JSON profile."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys

ARCH_FLAGS = {
    "x86_64": "__TARGET_ARCH_x86",
    "amd64": "__TARGET_ARCH_x86",
    "arm64": "__TARGET_ARCH_arm64",
    "aarch64": "__TARGET_ARCH_arm64",
}


def resolve_path(
    path: str | os.PathLike[str],
    base: pathlib.Path,
    *,
    must_exist: bool = False,
) -> pathlib.Path:
    candidate = pathlib.Path(path)
    if candidate.is_absolute():
        return candidate

    search_roots = [pathlib.Path.cwd(), base, base.parent]
    fallback = (base / candidate).resolve()

    for root in search_roots:
        resolved = (root / candidate).resolve()
        if not must_exist or resolved.exists():
            return resolved

    return fallback


def load_arch(config_path: pathlib.Path) -> str:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    arch = str(data.get("arch", "x86_64")).lower()
    if arch not in ARCH_FLAGS:
        raise SystemExit(f"unsupported arch '{arch}' in {config_path}")
    return arch


def invoke(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> None:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    default_config = repo_root / "configs" / "example.json"
    default_bpf = repo_root / "src" / "syscall_whitelist.bpf.c"
    default_header = repo_root / "src" / "generated_syscall_profiles.hpp"
    default_output = repo_root / "build" / "syscall_whitelist.bpf.o"

    parser = argparse.ArgumentParser(description="Compile the whitelist eBPF program")
    parser.add_argument(
        "--config",
        type=str,
        default=str(default_config),
        help="JSON profile config path",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(default_output),
        help="Output object file path",
    )
    parser.add_argument(
        "--clang",
        type=str,
        default=shutil.which("clang") or "clang",
        help="clang executable",
    )
    parser.add_argument(
        "--kernel-include",
        action="append",
        default=None,
        help="Additional include directory for kernel headers",
    )
    parser.add_argument(
        "--extra-cflags", nargs="*", default=None, help="Extra flags passed to clang"
    )
    parser.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="Add debug flags so EBPF program outputs debug info",
    )
    args = parser.parse_args()

    clang_path = shutil.which(args.clang)
    if clang_path is None:
        candidate = pathlib.Path(args.clang)
        if not candidate.exists():
            raise SystemExit(f"clang not found: {args.clang}")
        clang_path = str(candidate)

    config_path = resolve_path(args.config, repo_root, must_exist=True)
    if not config_path.is_file():
        raise SystemExit(f"config file not found: {config_path}")

    build_dir = default_output.parent
    build_dir.mkdir(parents=True, exist_ok=True)

    src_dir = repo_root / "src"
    generator = repo_root / "scripts" / "gen_syscall_whitelist_bpf.py"

    invoke(
        [
            sys.executable,
            str(generator),
            "--config",
            str(config_path),
            "--output",
            str(default_bpf),
            "--profile-header",
            str(default_header),
        ]
    )

    arch = load_arch(config_path)
    target_macro = ARCH_FLAGS[arch]

    cflags: list[str] = [
        "-O2",
        "-g",
        "-target",
        "bpf",
        f"-D{target_macro}",
        "-Wall",
        "-Werror",
        f"-I{src_dir}",
    ]

    if args.kernel_include:
        for inc in args.kernel_include:
            cflags.append(f"-I{resolve_path(inc, repo_root, must_exist=True)}")
    else:
        default_kernel_inc = pathlib.Path("/usr/include") / "x86_64-linux-gnu"
        if arch in {"x86_64", "amd64"} and default_kernel_inc.is_dir():
            cflags.append(f"-I{default_kernel_inc}")

    if args.extra_cflags:
        cflags.extend(args.extra_cflags)

    if args.debug:
        cflags.append("-DENABLE_BPF_DEBUG")

    output_path = resolve_path(args.output, repo_root)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    clang_cmd: list[str] = [
        clang_path,
        *cflags,
        "-c",
        str(default_bpf),
        "-o",
        str(output_path),
    ]

    invoke(clang_cmd)
    print(f"generated {output_path}")


if __name__ == "__main__":
    main()
