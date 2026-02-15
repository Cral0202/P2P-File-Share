import requests

from packaging import version
from constants import GITHUB_LATEST_RELEASE_API_URL, PROGRAM_VERSION

def program_version_up_to_date() -> bool:
    try:
        response = requests.get(GITHUB_LATEST_RELEASE_API_URL)
        latest_tag = response.json()["tag_name"].lstrip('v')

        if version.parse(latest_tag) > version.parse(PROGRAM_VERSION):
            return False

        return True
    except Exception:
        return True
