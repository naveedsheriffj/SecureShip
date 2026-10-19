import os
import shutil
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
EXAMPLES_DIR = BASE_DIR / "examples"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)

# Database
DATABASE_PATH = os.environ.get("SECURESHIP_DB_PATH", str(DATA_DIR / "secureship.db"))

# Application config
APP_VERSION = "1.0.0"
HOST = os.environ.get("SECURESHIP_HOST", "127.0.0.1")
PORT = int(os.environ.get("SECURESHIP_PORT", "5000"))
DEBUG = os.environ.get("SECURESHIP_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("SECURESHIP_SECRET_KEY", "secureship-local-dev-key-change-in-prod")

# Timeouts in seconds
TRIVY_TIMEOUT = int(os.environ.get("SECURESHIP_TRIVY_TIMEOUT", "120"))
DOCKER_BUILD_TIMEOUT = int(os.environ.get("SECURESHIP_BUILD_TIMEOUT", "240"))
DOCKER_RUN_TIMEOUT = int(os.environ.get("SECURESHIP_RUN_TIMEOUT", "30"))

# Deployment settings
DEPLOYMENT_HOST = "127.0.0.1"
DEPLOYMENT_PORT_MIN = int(os.environ.get("SECURESHIP_PORT_MIN", "5010"))
DEPLOYMENT_PORT_MAX = int(os.environ.get("SECURESHIP_PORT_MAX", "5050"))

# Tool binary detection
def find_trivy_path() -> str:
    """Find Trivy executable in PATH or known Windows install locations."""
    env_path = os.environ.get("TRIVY_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    # Check standard PATH
    path_which = shutil.which("trivy")
    if path_which:
        return path_which

    # Check Windows WinGet package location
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        winget_pkg_dir = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
        if winget_pkg_dir.exists():
            for p in winget_pkg_dir.glob("AquaSecurity.Trivy*/**/trivy.exe"):
                if p.is_file():
                    return str(p)

    return "trivy"


def find_docker_path() -> str:
    """Find Docker executable in PATH or known Windows install locations."""
    env_path = os.environ.get("DOCKER_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    path_which = shutil.which("docker")
    if path_which:
        return path_which

    # Check Docker Desktop bin folder
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        dd_bin = Path(local_app_data) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
        if dd_bin.exists():
            return str(dd_bin)

    program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
    pf_dd = Path(program_files) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe"
    if pf_dd.exists():
        return str(pf_dd)

    return "docker"

TRIVY_BIN = find_trivy_path()
DOCKER_BIN = find_docker_path()

# Allowed image reference pattern
# Alphanumeric with slashes, colons (including registry port and tags), underscores, dashes, dots.
# Strictly rejects shell metacharacters: ;, &, |, `, $, >, <, \n, spaces, etc.
IMAGE_REF_REGEX = r"^[a-zA-Z0-9]+([._\-\/:][a-zA-Z0-9]+)*(@sha256:[a-fA-F0-9]{64})?$"

# Bundled sample images allowlist
ALLOWED_BUNDLED_APPS = {
    "sample-python-app": "Secured Python 3.11 Microservice (Clean Base)",
    "vulnerable-python-app": "Deliberately Insecure Python App (High/Critical CVEs)"
}
