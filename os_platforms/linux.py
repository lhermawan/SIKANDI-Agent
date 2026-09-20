import os
import platform
import subprocess
from pathlib import Path


class LinuxPlatform:
    """
    Linux-specific utilities for SIKANDI Agent.

    This class is responsible only for interacting with the Linux OS.
    Detection, risk scoring, correlation, and incident creation should
    remain in collectors/detectors/security modules.
    """

    def __init__(self):
        if platform.system().lower() != "linux":
            raise RuntimeError(
                "LinuxPlatform can only be used on Linux systems."
            )

    # =========================================================
    # SYSTEM INFORMATION
    # =========================================================

    def get_hostname(self):
        """
        Get system hostname.
        """
        return platform.node()

    def get_os_info(self):
        """
        Get Linux distribution and kernel information.
        """

        return {
            "system": "Linux",
            "distribution": self._get_distribution(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "hostname": self.get_hostname(),
        }

    def _get_distribution(self):
        """
        Read Linux distribution from /etc/os-release.
        """

        os_release = Path("/etc/os-release")

        if not os_release.exists():
            return "Linux"

        data = {}

        try:
            with os_release.open(
                "r",
                encoding="utf-8"
            ) as file:

                for line in file:
                    line = line.strip()

                    if not line or "=" not in line:
                        continue

                    key, value = line.split("=", 1)

                    data[key] = value.strip('"')

            return data.get(
                "PRETTY_NAME",
                data.get("NAME", "Linux")
            )

        except (OSError, PermissionError):
            return "Linux"

    def get_kernel(self):
        """
        Get Linux kernel version.
        """
        return platform.release()

    def get_architecture(self):
        """
        Get CPU architecture.
        """
        return platform.machine()

    # =========================================================
    # UPTIME
    # =========================================================

    def get_uptime(self):
        """
        Get system uptime in seconds.
        """

        uptime_file = Path("/proc/uptime")

        try:
            with uptime_file.open(
                "r",
                encoding="utf-8"
            ) as file:

                uptime = float(
                    file.read().split()[0]
                )

            return int(uptime)

        except (
            OSError,
            ValueError,
            IndexError
        ):
            return 0

    def get_uptime_info(self):
        """
        Get uptime in multiple formats.
        """

        seconds = self.get_uptime()

        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60

        return {
            "seconds": seconds,
            "days": days,
            "hours": hours,
            "minutes": minutes,
        }

    # =========================================================
    # CURRENT LOGGED-IN USERS
    # =========================================================

    def get_logged_in_users(self):
        """
        Get users currently logged into the system.

        Uses the Linux 'who' command.
        """

        users = []

        result = self.run_command(
            ["who"],
            timeout=5
        )

        if not result["success"]:
            return users

        for line in result["stdout"].splitlines():

            parts = line.split()

            if not parts:
                continue

            user = {
                "username": parts[0],
            }

            if len(parts) >= 2:
                user["terminal"] = parts[1]

            if len(parts) >= 4:
                user["login_time"] = (
                    f"{parts[2]} {parts[3]}"
                )

            if len(parts) >= 5:
                source = parts[4]

                user["source"] = source.strip("()")

            users.append(user)

        return users

    # =========================================================
    # AUTHENTICATION LOG
    # =========================================================

    def get_auth_log_path(self):
        """
        Detect authentication log location.

        Ubuntu/Debian:
            /var/log/auth.log

        RHEL/CentOS:
            /var/log/secure
        """

        paths = [
            "/var/log/auth.log",
            "/var/log/secure",
        ]

        for path in paths:

            if os.path.isfile(path):
                return path

        return None

    def has_auth_log(self):
        """
        Check whether authentication log exists.
        """

        return self.get_auth_log_path() is not None

    # =========================================================
    # SYSTEMD
    # =========================================================

    def has_systemd(self):
        """
        Check whether systemd is available.
        """

        return (
            os.path.exists("/run/systemd/system")
            or self.command_exists("systemctl")
        )

    def get_systemd_status(self):
        """
        Get basic systemd status.
        """

        if not self.command_exists("systemctl"):
            return {
                "available": False,
                "running": False,
            }

        result = self.run_command(
            [
                "systemctl",
                "is-system-running",
            ],
            timeout=5
        )

        status = result["stdout"]

        return {
            "available": True,
            "running": status in (
                "running",
                "degraded",
            ),
            "status": status or "unknown",
        }

    # =========================================================
    # COMMAND UTILITIES
    # =========================================================

    def command_exists(self, command):
        """
        Check whether a command exists.
        """

        result = subprocess.run(
            ["which", command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )

        return result.returncode == 0

    def run_command(self, command, timeout=10):
        """
        Execute a system command.

        Intended for read-only/system inspection commands.

        Returns:
            {
                "success": bool,
                "stdout": str,
                "stderr": str,
                "returncode": int
            }
        """

        try:

            if isinstance(command, str):
                command = command.split()

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode,
            }

        except subprocess.TimeoutExpired:

            return {
                "success": False,
                "stdout": "",
                "stderr": "Command timed out",
                "returncode": -1,
            }

        except FileNotFoundError:

            return {
                "success": False,
                "stdout": "",
                "stderr": "Command not found",
                "returncode": -1,
            }

        except PermissionError:

            return {
                "success": False,
                "stdout": "",
                "stderr": "Permission denied",
                "returncode": -1,
            }

        except Exception as e:

            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
            }

    # =========================================================
    # FILE UTILITIES
    # =========================================================

    def file_exists(self, path):
        """
        Check whether a file exists.
        """

        return os.path.isfile(path)

    def directory_exists(self, path):
        """
        Check whether a directory exists.
        """

        return os.path.isdir(path)

    def read_file(self, path, max_bytes=1024 * 1024):
        """
        Safely read a text file.

        max_bytes prevents accidentally loading huge files.
        """

        try:

            file_path = Path(path)

            if not file_path.is_file():
                return None

            if file_path.stat().st_size > max_bytes:
                return None

            return file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )

        except (
            OSError,
            PermissionError,
        ):
            return None

    # =========================================================
    # IMPORTANT LINUX PATHS
    # =========================================================

    def get_important_paths(self):
        """
        Return important Linux paths used by security collectors.
        """

        return {
            "auth_log": self.get_auth_log_path(),
            "passwd": "/etc/passwd",
            "shadow": "/etc/shadow",
            "group": "/etc/group",
            "sudoers": "/etc/sudoers",
            "ssh_directory": "/etc/ssh",
            "systemd_directory": "/etc/systemd/system",
            "cron_directory": "/etc/cron.d",
            "tmp_directory": "/tmp",
        }

    # =========================================================
    # PLATFORM SUMMARY
    # =========================================================

    def get_summary(self):
        """
        Return a compact Linux system summary.
        """

        uptime = self.get_uptime_info()
        systemd = self.get_systemd_status()

        return {
            "hostname": self.get_hostname(),
            "os": self._get_distribution(),
            "kernel": self.get_kernel(),
            "architecture": self.get_architecture(),
            "uptime_seconds": uptime["seconds"],
            "uptime_days": uptime["days"],
            "auth_log": self.get_auth_log_path(),
            "systemd": systemd,
        }