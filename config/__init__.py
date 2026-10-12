from pathlib import Path

from pydantic_settings import BaseSettings

from utils import get_current_time


class CaptureSettings(BaseSettings):
    capture_output: str = f"./captured/{get_current_time()}"
    capture_chunk: int = 10
    capture_duration: int = 0
    capture_filter_rule: str = ""


class ProfileConvertSettings(BaseSettings):
    trim_gomod_path: bool = False
    gomod_path: str = str(Path.home() / "go" / "pkg" / "mod")


capture_settings = CaptureSettings()
profile_convert_settings = ProfileConvertSettings()
