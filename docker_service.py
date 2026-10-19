"""
SecureShip Docker Service

Provides safe, controlled Docker operations via subprocess argument lists.
Restricts builds to known bundled directories and restricts deployments to localhost.
"""

import os
import re
import time
import socket
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from config import (
    DOCKER_BIN,
    EXAMPLES_DIR,
    DOCKER_BUILD_TIMEOUT,
    DOCKER_RUN_TIMEOUT,
    ALLOWED_BUNDLED_APPS,
    DEPLOYMENT_HOST,
    DEPLOYMENT_PORT_MIN,
    DEPLOYMENT_PORT_MAX
)

logger = logging.getLogger(__name__)

class DockerServiceError(RuntimeError):
    pass

class DockerService:
    """Safely executes Docker commands without shell=True."""

    @staticmethod
    def get_docker_status() -> Tuple[bool, str]:
        """Verify Docker executable and daemon connection."""
        try:
            res = subprocess.run(
                [DOCKER_BIN, "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                return True, f"Docker Engine {res.stdout.strip()}"
            
            # Check if client works but daemon is down
            client_res = subprocess.run(
                [DOCKER_BIN, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            client_ver = client_res.stdout.strip() if client_res.returncode == 0 else "Docker CLI"
            err = res.stderr.strip() or "Docker daemon is not responding or not started."
            return False, f"{client_ver} (Daemon unavailable: {err[:120]})"
        except FileNotFoundError:
            return False, f"Docker binary '{DOCKER_BIN}' not found in system."
        except subprocess.TimeoutExpired:
            return False, "Timed out communicating with Docker daemon."
        except Exception as e:
            return False, f"Error communicating with Docker: {str(e)}"

    @classmethod
    def inspect_image(cls, image_ref: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Inspect image to retrieve immutable Image ID and repo digest.
        Returns (exists, image_id, repo_digest).
        """
        try:
            res = subprocess.run(
                [DOCKER_BIN, "image", "inspect", "--format", "{{.Id}}|{{index .RepoDigests 0}}", image_ref],
                capture_output=True,
                text=True,
                timeout=15,
                check=False
            )
            if res.returncode == 0 and res.stdout.strip():
                parts = res.stdout.strip().split("|")
                img_id = parts[0] if len(parts) > 0 and parts[0] != "<no value>" else None
                digest = parts[1] if len(parts) > 1 and parts[1] != "<no value>" else None
                return True, img_id, digest
            return False, None, None
        except Exception as e:
            logger.warning("Failed to inspect image %s: %s", image_ref, str(e))
            return False, None, None

    @classmethod
    def build_bundled_image(cls, app_key: str, tag: str) -> Dict[str, Any]:
        """
        Build a Docker image from a known bundled directory in examples/.
        Refuses arbitrary directories from users.
        """
        if app_key not in ALLOWED_BUNDLED_APPS:
            raise DockerServiceError(
                f"Unauthorized app key '{app_key}'. Allowed bundled examples: {list(ALLOWED_BUNDLED_APPS.keys())}"
            )

        app_dir = EXAMPLES_DIR / app_key
        dockerfile = app_dir / "Dockerfile"
        if not dockerfile.is_file():
            raise DockerServiceError(f"Dockerfile not found in bundled app directory: {app_dir}")

        docker_avail, docker_msg = cls.get_docker_status()
        if not docker_avail:
            raise DockerServiceError(f"Cannot build image. Docker is unavailable: {docker_msg}")

        # Validate tag
        from scanner import ScannerService
        validated_tag = ScannerService.validate_image_reference(tag)

        cmd = [
            DOCKER_BIN,
            "build",
            "-t", validated_tag,
            str(app_dir)
        ]

        logger.info("Building Docker image: %s (Directory: %s)", " ".join(cmd), app_dir)
        start_time = time.time()

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=DOCKER_BUILD_TIMEOUT,
                check=False
            )
            duration = round(time.time() - start_time, 2)
            
            if res.returncode != 0:
                logger.error("Docker build failed: %s", res.stderr)
                return {
                    "success": False,
                    "image_ref": validated_tag,
                    "duration_seconds": duration,
                    "output": res.stdout + "\n" + res.stderr,
                    "error": f"Docker build returned exit code {res.returncode}",
                    "image_id": None
                }

            # Retrieve immutable image ID
            _, img_id, digest = cls.inspect_image(validated_tag)

            return {
                "success": True,
                "image_ref": validated_tag,
                "duration_seconds": duration,
                "output": res.stdout,
                "error": None,
                "image_id": img_id,
                "image_digest": digest
            }
        except subprocess.TimeoutExpired:
            duration = round(time.time() - start_time, 2)
            raise DockerServiceError(f"Docker build timed out after {DOCKER_BUILD_TIMEOUT} seconds.")
        except Exception as e:
            raise DockerServiceError(f"Error during Docker build: {str(e)}")

    @staticmethod
    def find_free_port(start_port: int = DEPLOYMENT_PORT_MIN, end_port: int = DEPLOYMENT_PORT_MAX) -> int:
        """Find an available port on 127.0.0.1 within the restricted range."""
        for port in range(start_port, end_port + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind((DEPLOYMENT_HOST, port))
                    return port
                except OSError:
                    continue
        raise DockerServiceError(f"No available ports in range {start_port}-{end_port}.")

    @classmethod
    def run_container(cls, image_ref: str, container_name: str, host_port: int, target_port: int = 5000) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Run container bound strictly to 127.0.0.1 with resource limits.
        Never runs privileged mode.
        """
        cmd = [
            DOCKER_BIN,
            "run",
            "-d",
            "--name", container_name,
            "-p", f"{DEPLOYMENT_HOST}:{host_port}:{target_port}",
            "--memory", "256m",
            "--cpus", "0.5",
            "--restart", "no",
            image_ref
        ]

        logger.info("Running container: %s", " ".join(cmd))
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=DOCKER_RUN_TIMEOUT,
                check=False
            )
            if res.returncode == 0:
                container_id = res.stdout.strip()[:12]
                return True, container_id, None
            return False, None, res.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, None, f"Container start timed out after {DOCKER_RUN_TIMEOUT} seconds."
        except Exception as e:
            return False, None, f"Subprocess error: {str(e)}"

    @classmethod
    def stop_container(cls, container_id_or_name: str) -> Tuple[bool, Optional[str]]:
        """
        Stop and remove a container managed by SecureShip.
        """
        # Validate container ID/name string format to prevent parameter injection
        if not re.match(r"^[a-zA-Z0-9_\-]+$", container_id_or_name):
            return False, "Invalid container identifier format."

        try:
            # Stop container
            res_stop = subprocess.run(
                [DOCKER_BIN, "stop", "-t", "5", container_id_or_name],
                capture_output=True,
                text=True,
                timeout=15,
                check=False
            )
            # Remove container to free name and port
            subprocess.run(
                [DOCKER_BIN, "rm", "-f", container_id_or_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            if res_stop.returncode == 0:
                return True, None
            return False, res_stop.stderr.strip()
        except Exception as e:
            return False, str(e)
