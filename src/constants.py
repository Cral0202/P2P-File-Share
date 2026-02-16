from pathlib import Path

PROGRAM_VERSION = "1.3.3"
GITHUB_LATEST_RELEASE_URL = "https://github.com/Cral0202/P2P-File-Share/releases/latest"
GITHUB_LATEST_RELEASE_API_URL = "https://api.github.com/repos/Cral0202/P2P-File-Share/releases/latest"

BASE_DIR = Path.home() / ".p2p_file_share"
BASE_DIR.mkdir(parents=True, exist_ok=True)
