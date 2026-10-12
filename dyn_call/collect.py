import os.path
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from config import profile_convert_settings


def is_standard_import_path(path: str) -> bool:
    i = path.find("/")
    if i < 0:
        i = len(path)
    elem = path[:i]
    return "." not in elem


@dataclass(slots=True)
class FuncName:
    is_ptr: bool
    pkg: str
    typ: str | None
    name: str

    def format_ssa_name(self) -> str:
        parts = []
        if self.is_ptr:
            parts.append("*")
        parts.append(self.pkg)
        if self.typ:
            parts.insert(0, "(")
            parts.append(f".{self.typ})")
        if self.name:
            parts.append(f".{self.name}")
        return "".join(parts)

    def format_compiler_name(self) -> str:
        parts = []
        parts.append(self.pkg)
        if self.typ:
            if self.is_ptr:
                parts.append(f".(*{self.typ})")
            else:
                parts.append(f".{self.typ}")
        parts.append(f".{self.name}")
        return "".join(parts)

    @staticmethod
    def _split_runtime_parts(name: str) -> list[str]:
        parts: list[str] = []
        buf: list[str] = []
        depth = 0
        for ch in name:
            if ch == "[":
                depth += 1
            elif ch == "]" and depth > 0:
                depth -= 1
            if ch == "." and depth == 0:
                parts.append("".join(buf))
                buf = []
                continue
            buf.append(ch)
        parts.append("".join(buf))
        return parts

    @classmethod
    def from_runtime_name(cls, name: str) -> "FuncName":
        # hostname may contain "."
        hostname = None
        if "/" in name:
            hostname, others = name.split("/", 1)
            if "." in hostname:
                name = others
        parts = cls._split_runtime_parts(name)
        parts[0] = hostname + "/" + parts[0] if hostname else parts[0]

        # check lambda: last part is func%d
        last = parts[-1]
        if (
            last.startswith("func")
            or last.startswith("deferwrap")
            or last.startswith("gowrap")
            or last.isnumeric()
        ):
            lambda_name = parts[-1]
            parts = parts[:-1]
            parts[-1] += f".{lambda_name}"

        is_ptr = False
        match len(parts):
            case 2:  # pkg.name
                pkg, name = parts
                typ = None
            case 3:  # pkg.typ.name
                pkg, typ, name = parts
                if typ.startswith("(*"):
                    is_ptr = True
                    typ = typ[2:-1]
            case _:
                raise ValueError(f"Invalid runtime func name: {name}")

        return cls(
            is_ptr=is_ptr,
            pkg=pkg,
            typ=typ,
            name=name,
        )


class CallLog(BaseModel):
    kind: Literal["iface", "reflect", "dynamic"]
    file: str
    line: int
    col: int
    caller: str
    type: str
    type_pkgpath: str | None = None
    type_name: str | None = None
    method: str | None = None
    func: str | None = None

    @staticmethod
    def _split_type_args(type_args: str) -> list[str]:
        args: list[str] = []
        buf: list[str] = []
        square = 0
        paren = 0
        brace = 0
        for ch in type_args:
            if ch == "[":
                square += 1
            elif ch == "]" and square > 0:
                square -= 1
            elif ch == "(":
                paren += 1
            elif ch == ")" and paren > 0:
                paren -= 1
            elif ch == "{":
                brace += 1
            elif ch == "}" and brace > 0:
                brace -= 1

            if ch == "," and square == 0 and paren == 0 and brace == 0:
                arg = "".join(buf).strip()
                if arg:
                    args.append(arg)
                buf = []
                continue
            buf.append(ch)

        tail = "".join(buf).strip()
        if tail:
            args.append(tail)
        return args

    def get_callee_func_name(self) -> FuncName:
        match self.kind:
            case "iface":
                assert self.method is not None
                is_ptr = self.type.startswith("*")
                pkg_typ = self.type[1:] if is_ptr else self.type

                typevar = None
                if "[" in pkg_typ and pkg_typ.endswith("]"):
                    # Handle generic types, e.g. pkg.Type[T] or pkg.Type[interface {}].
                    type_args_raw = pkg_typ[pkg_typ.find("[") + 1 : -1]
                    pkg_typ = pkg_typ[: pkg_typ.find("[")]
                    normalized_args: list[str] = []
                    for arg in self._split_type_args(type_args_raw):
                        try:
                            normalized_args.append(
                                FuncName.from_runtime_name(arg).format_ssa_name()
                            )
                        except ValueError:
                            # Some type arguments are not runtime symbol names.
                            # Keep their original textual form to avoid dropping logs.
                            normalized_args.append(arg)
                    if normalized_args:
                        typevar = ", ".join(normalized_args)

                pkg, typ = pkg_typ.rsplit(".", 1)
                if typevar:
                    typ = f"{typ}[{typevar}]"
                name = self.method
            case "reflect":
                assert self.func is not None
                is_ptr = self.func.startswith("*")
                pkg_name = self.func[1:] if is_ptr else self.func
                pkg, name = pkg_name.rsplit(".", 1)
                typ = None
            case "dynamic":
                # Dynamic calls have func field like "pkg.(*Type).method" or "pkg.func"
                assert self.func is not None
                func_name = self.func

                # Check if it's a method call with pointer receiver
                is_ptr = False
                if "(*" in func_name and ")" in func_name:
                    is_ptr = True
                    # Extract pkg.(*Type).method -> pkg.Type.method
                    # Find the pattern pkg.(*Type).method
                    import re

                    match = re.match(r"^(.+)\.\(\*([^)]+)\)\.(.+)$", func_name)
                    if match:
                        pkg = match.group(1)
                        typ = match.group(2)
                        name = match.group(3)
                    else:
                        # Fallback: try to parse as regular function
                        parts = func_name.rsplit(".", 1)
                        if len(parts) == 2:
                            pkg, name = parts
                            typ = None
                        else:
                            raise ValueError(f"Invalid dynamic func name: {func_name}")
                else:
                    # Regular function call: pkg.func or pkg.Type.func
                    parts = func_name.rsplit(".", 1)
                    if len(parts) == 2:
                        pkg_name_part, name = parts
                        # Check if it's a method call (pkg.Type.func)
                        if "." in pkg_name_part:
                            pkg, typ = pkg_name_part.rsplit(".", 1)
                        else:
                            pkg = pkg_name_part
                            typ = None
                    else:
                        raise ValueError(f"Invalid dynamic func name: {func_name}")
            case _:
                raise ValueError(f"Unknown log kind: {self.kind}")
        return FuncName(
            is_ptr=is_ptr,
            pkg=pkg,
            typ=typ,
            name=name,
        )


@dataclass(slots=True, frozen=True)
class CallSite:
    file: str
    func: str
    line: int
    col: int


@dataclass(slots=True)
class CallLogsCollector:
    project_path: Path
    project_mod_name: str
    log_path: Path

    def parse_log_line(self, line: str) -> tuple[CallSite, str]:
        log = CallLog.model_validate_json(line)

        file = log.file
        if profile_convert_settings.trim_gomod_path and file.startswith(
            profile_convert_settings.gomod_path
        ):
            # Trim the module path prefix
            file = file[len(profile_convert_settings.gomod_path) + 1 :]
        elif file.startswith(str(self.project_path)):
            file = os.path.relpath(file, start=str(self.project_path))

        caller_str = log.caller
        caller, line, col = caller_str.rsplit(":", 2)
        row = int(line)
        col = int(col)

        callsite = CallSite(
            file=str(file),
            func=caller,
            line=row,
            col=col,
        )

        callee = log.get_callee_func_name()

        if is_standard_import_path(callee.pkg) and log.type_pkgpath:
            # rtype.string() only contain the package path without hostname
            callee.pkg = log.type_pkgpath

        callee = callee.format_compiler_name()
        callee += f":{log.line}:{log.col}"

        return callsite, callee

    def read_logs(self) -> list[tuple[CallSite, str]]:
        logs: list[tuple[CallSite, str]] = []
        with open(self.log_path, "r") as f:
            for line in f:
                try:
                    caller, callee = self.parse_log_line(line)
                except:
                    print(f"Failed to parse log line: {line}")
                    continue
                logs.append((caller, callee))
        return logs
