#!/usr/bin/env python3
"""Build a matching eBPF object and syscall loader from one whitelist config.

This avoids compiling the loader against a stale shared
`generated_syscall_profiles.hpp` left behind by another config build.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys


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


def invoke(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> None:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    src_dir = repo_root / "src"
    shared_header = src_dir / "generated_syscall_profiles.hpp"
    build_bpf_script = repo_root / "scripts" / "build_whitelist_module.py"

    parser = argparse.ArgumentParser(
        description="Build matching whitelist eBPF and loader artifacts"
    )
    parser.add_argument("--config", required=True, help="JSON profile config path")
    parser.add_argument("--bpf-output", required=True, help="Output BPF object path")
    parser.add_argument(
        "--loader-output", required=True, help="Output syscall loader path"
    )
    parser.add_argument(
        "--profile-snapshot-output",
        default=None,
        help="Optional copy of the generated profile header for this loader",
    )
    parser.add_argument(
        "--clang",
        type=str,
        default=shutil.which("clang") or "clang",
        help="clang executable passed through to build_whitelist_module.py",
    )
    parser.add_argument(
        "--cxx",
        type=str,
        default=shutil.which("g++") or shutil.which("c++") or "g++",
        help="C++ compiler for syscall_loader",
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
        "--extra-cxxflags",
        nargs="*",
        default=None,
        help="Extra flags passed to the C++ compiler",
    )
    parser.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="Add debug flags so EBPF program outputs debug info",
    )
    args = parser.parse_args()

    config_path = resolve_path(args.config, repo_root, must_exist=True)
    bpf_output = resolve_path(args.bpf_output, repo_root)
    loader_output = resolve_path(args.loader_output, repo_root)
    snapshot_output = (
        resolve_path(args.profile_snapshot_output, repo_root)
        if args.profile_snapshot_output
        else loader_output.with_name(f"{loader_output.name}.generated_syscall_profiles.hpp")
    )

    bpf_output.parent.mkdir(parents=True, exist_ok=True)
    loader_output.parent.mkdir(parents=True, exist_ok=True)
    snapshot_output.parent.mkdir(parents=True, exist_ok=True)

    build_bpf_cmd = [
        sys.executable,
        str(build_bpf_script),
        "--config",
        str(config_path),
        "--output",
        str(bpf_output),
        "--clang",
        args.clang,
    ]
    if args.kernel_include:
        for inc in args.kernel_include:
            build_bpf_cmd.extend(["--kernel-include", inc])
    if args.extra_cflags:
        build_bpf_cmd.extend(["--extra-cflags", *args.extra_cflags])
    if args.debug:
        build_bpf_cmd.append("--debug")

    invoke(build_bpf_cmd)

    shutil.copy2(shared_header, snapshot_output)

    cxx_cmd = [
        args.cxx,
        "-std=c++17",
        "-O2",
        "-Wall",
        "-Wextra",
        "-pedantic",
        str(src_dir / "syscall_whitelist.cpp"),
        f"-I{src_dir}",
    ]
    if args.extra_cxxflags:
        cxx_cmd.extend(args.extra_cxxflags)
    cxx_cmd.extend(["-lbpf", "-lelf", "-lz", "-o", str(loader_output)])

    invoke(cxx_cmd)

    print(f"generated {bpf_output}")
    print(f"generated {loader_output}")
    print(f"snapshot  {snapshot_output}")


if __name__ == "__main__":
    main()
