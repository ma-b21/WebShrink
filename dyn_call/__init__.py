import json
from pathlib import Path

from dyn_call.collect import CallLogsCollector


def export_dyn_calls(
    project_path: Path,
    export_path: Path = Path("."),
    log_path: Path = Path("/tmp/ifacecalls.log"),
) -> None:
    go_mod_path = project_path / "go.mod"
    if not go_mod_path.exists():
        raise ValueError(f"Cannot find go.mod in {project_path}")
    project_mod_name = ""
    with open(go_mod_path, "r") as f:
        for line in f:
            if line.startswith("module "):
                project_mod_name = line.strip().split(" ")[1]
                break
    if not project_mod_name:
        raise ValueError(f"Cannot find module name in {go_mod_path}")

    collector = CallLogsCollector(
        project_path=project_path,
        project_mod_name=project_mod_name,
        log_path=log_path,
    )
    logs = collector.read_logs()

    export = {}
    for callsite, callee in logs:
        export.setdefault(
            callsite.func,
            {
                "file": callsite.file,
                "line": callsite.line,
                "col": callsite.col,
                "callee": set(),
            },
        )["callee"].add(callee)

    export_file = export_path / "dyn_calls.json"
    export_serializable = {
        func: {**data, "callee": list(data["callee"])} for func, data in export.items()
    }
    with open(export_file, "w") as f:
        json.dump(export_serializable, f, indent=2)
