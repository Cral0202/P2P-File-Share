from pathlib import Path

PROGRAM_VERSION = "1.0.0"

BASE_DIR = Path.home() / ".p2p_file_share"
BASE_DIR.mkdir(parents=True, exist_ok=True)
