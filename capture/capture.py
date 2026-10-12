import glob
import itertools
import os
import signal
import subprocess
import time
from typing import Any, Generator, Iterable, NoReturn

import orjson as json
from loguru import logger
from rich import print

from config import capture_settings
from parse import Log, LogCombiner, process_format


def prepare(output: str) -> None:
    """
    - Create the output directory if it doesn't exist.
    """
    os.makedirs(output, exist_ok=True)


def exec_command(command: str) -> None:
    print(command)
    os.system(command)


def spawn_sysdig(
    output: str, chunk: int, duration: int, filter_: str
) -> tuple[subprocess.Popen[Any], str]:
    """
    - Spawn a subprocess to run sysdig.
    - Capture the output to a file in the output directory.
    """

    print("Spawning Sysdig subprocess...")

    filter_rule = "((evt.category=net or evt.category=file or evt.category=process) and container.id!='host' and container.id!='')"
    if filter_:
        filter_rule = filter_rule + " and " + filter_

    print(f"Filter: {filter_rule}")

    clear_command = f"sudo rm {output}/capture.scap*"
    exec_command(clear_command)

    command = ["sudo"]
    if duration != 0:
        command += ["timeout", str(duration)]
    command += [
        "sysdig",
        "-C",
        str(chunk),
        filter_rule,
        "-w",
        f"{output}/capture.scap",
    ]
    print(command)
    with (
        open("./sysdig_output.log", "w") as outfile,
        open("./sysdig_error.log", "w") as errfile,
    ):
        sysdig_process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=outfile,
            stderr=errfile,
            preexec_fn=os.setsid,
        )
        time.sleep(2)
        if sysdig_process.poll() is not None:
            with open("./sysdig_error.log", "r") as errfile:
                error_message = errfile.read()
            raise RuntimeError(f"Sysdig failed to start: {error_message}")
    return sysdig_process, filter_rule


def read_chunk(
    path: str, filter_rule: str, fields_string: str | None
) -> Generator[str, Any, None]:
    command = ["sysdig"]
    if fields_string:
        command += ["-p", fields_string]
    command += [
        "-j",
        "-r",
        path,
        filter_rule,
    ]
    print(command)
    reader_process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, _ = reader_process.communicate()
    for line in stdout.decode().split("\n"):
        yield line


class ChunkTracker:
    """Track chunk ingestion so we can resume after interruptions."""

    def __init__(
        self, output: str, filter_rule: str, fields_string: str | None
    ) -> None:
        self.output = output
        self.filter_rule = filter_rule
        self.fields_string = fields_string
        self.current_id = 0
        self._line_offsets: dict[int, int] = {}

    def _chunk_path(self, chunk_id: int) -> str:
        return f"{self.output}/capture.scap{chunk_id}"

    def _chunk_index(self, path: str) -> int:
        name = os.path.basename(path)
        suffix = name.replace("capture.scap", "", 1)
        return int(suffix) if suffix.isdigit() else 0

    def _existing_chunks(self) -> list[str]:
        pattern = os.path.join(self.output, "capture.scap*")
        return sorted(glob.glob(pattern), key=self._chunk_index)

    def _consume_chunk(self, path: str, chunk_id: int) -> Generator[str, Any, None]:
        line_index = self._line_offsets.get(chunk_id, 0)
        for logline in read_chunk(path, self.filter_rule, self.fields_string):
            line_index += 1
            self._line_offsets[chunk_id] = line_index
            yield logline
        if os.path.exists(path):
            os.remove(path)
        self._line_offsets.pop(chunk_id, None)

    def stream(self) -> Generator[str, Any, NoReturn]:
        while True:
            next_path = self._chunk_path(self.current_id + 1)
            current_path = self._chunk_path(self.current_id)
            if os.path.exists(next_path):
                yield from self._consume_chunk(current_path, self.current_id)
                self.current_id += 1
            else:
                time.sleep(1)

    def drain_remaining(self) -> Generator[str, Any, None]:
        for path in self._existing_chunks():
            chunk_id = self._chunk_index(path)
            skip = self._line_offsets.get(chunk_id, 0)
            line_index = 0
            for logline in read_chunk(path, self.filter_rule, self.fields_string):
                line_index += 1
                if line_index <= skip:
                    continue
                yield logline
            if os.path.exists(path):
                os.remove(path)
            self._line_offsets.pop(chunk_id, None)
            if chunk_id == self.current_id:
                self.current_id += 1


def parse_log(
    log_lines: Iterable[str],
    combiner: LogCombiner | None,
) -> Generator[Log, None, None]:
    for logline in log_lines:
        if logline:
            data = json.loads(logline)
            data = process_format(data)
            if combiner:
                data = combiner.parse(data)
            if data:
                yield data


def parse_fields_string(fields: Iterable[str] | None) -> None | str:
    if not fields:
        return None
    fixed_fields = ["container.id", "thread.tid"]
    return "*" + " ".join([f"%{f}" for f in itertools.chain(fixed_fields, fields)])


def capture(
    output: str = capture_settings.capture_output,
    chunk: int = capture_settings.capture_chunk,
    duration: int = capture_settings.capture_duration,
    filter_rule: str = capture_settings.capture_filter_rule,
) -> Generator[Log, None, None]:
    print(f"Capturing to: {output}")

    # Preparation
    prepare(output)

    sysdig_process, filter_rule = spawn_sysdig(output, chunk, duration, filter_rule)

    fields_string = parse_fields_string(
        {
            "container.id",
            "evt.arg.data",
            "evt.arg.filename",
            "evt.arg.newpath",
            "evt.arg.oldpath",
            "evt.arg.pid",
            "evt.args",
            "evt.arg.arg3",
            "evt.buffer",
            "evt.category",
            "evt.datetime",
            "evt.dir",
            "evt.is_io_read",
            "evt.is_io_write",
            "evt.num",
            "evt.rawres",
            "evt.time",
            "evt.type",
            "fd.cip",
            "fd.cport",
            "fd.directory",
            "fd.ino",
            "fd.is_server",
            "fd.lip",
            "fd.name",
            "fd.num",
            "fd.rip",
            "fd.sip",
            "fd.sport",
            "fd.type",
            "proc.cmdline",
            "proc.exepath",
            "proc.name",
            "proc.pid",
            "proc.vpid",
            "thread.tid",
            "thread.vtid",
        }
    )
    tracker = ChunkTracker(output, filter_rule, fields_string)
    combiner = LogCombiner()

    try:
        # Parse Sysdig Output
        for log in parse_log(tracker.stream(), combiner):
            yield log
    except Exception as e:
        logger.exception(e)
    except KeyboardInterrupt:
        logger.info(
            "Capture interrupted by user. Draining remaining events before exit."
        )
        if sysdig_process:
            _terminate_process(sysdig_process)
        for log in parse_log(tracker.drain_remaining(), combiner):
            yield log
        return
    finally:
        if sysdig_process:
            _terminate_process(sysdig_process)


def _terminate_process(process: subprocess.Popen[Any]) -> None:
    """Gracefully stop sysdig so it can flush current chunk to disk."""
    if process.poll() is not None:
        return

    # Use SIGINT first (same as Ctrl+C) so sysdig can finalize an in-progress scap.
    try:
        pgid = os.getpgid(process.pid)
        os.killpg(pgid, signal.SIGINT)
    except ProcessLookupError:
        return
    except Exception:
        process.send_signal(signal.SIGINT)

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
