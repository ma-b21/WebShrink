"""Export dynamic call edges from a benign instrumented application run."""

import argparse
from pathlib import Path

from dyn_call import export_dyn_calls


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True, help="Go module directory")
    parser.add_argument("--output", type=Path, required=True, help="Output directory")
    parser.add_argument("--log", type=Path, default=Path("/tmp/ifacecalls.log"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    export_dyn_calls(args.project.resolve(), args.output.resolve(), args.log.resolve())


if __name__ == "__main__":
    main()
