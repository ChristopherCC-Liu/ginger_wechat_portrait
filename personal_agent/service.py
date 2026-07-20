"""User-level LaunchAgent installation and operational safety controls."""

from __future__ import annotations

import os
import platform
import plistlib
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .config import AgentConfig, AgentPaths
from .storage import atomic_write_text, ensure_private_dir


LAUNCH_AGENT_LABEL = "com.christophercc.ginger-agent"


def validate_agent_executable(executable: Path) -> Path:
    """Validate the immutable console entry point used by launchd."""
    candidate = executable.expanduser()
    if not candidate.is_absolute():
        raise ValueError("Agent executable must be an absolute path")
    candidate = candidate.absolute()
    interpreter_dir = Path(sys.executable).expanduser().absolute().parent
    if candidate.parent != interpreter_dir:
        raise ValueError(
            "Agent executable must be in the current interpreter directory"
        )
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise ValueError(f"Agent executable is missing: {candidate}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"Refusing symbolic-link agent executable: {candidate}")
    if not stat.S_ISREG(metadata.st_mode) or not os.access(candidate, os.X_OK):
        raise ValueError(f"Agent executable is not executable: {candidate}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError("Agent executable is not owned by the current user")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("Agent executable must not be group- or world-writable")
    return candidate


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class ServiceManager:
    def __init__(
        self,
        paths: AgentPaths,
        executable: Path,
        config_path: Path,
        poll_interval_seconds: int,
        *,
        runner: Any = subprocess.run,
    ) -> None:
        self.paths = paths
        self.executable = executable.expanduser().absolute()
        self.config_path = config_path.expanduser().absolute()
        self.poll_interval = max(5, int(poll_interval_seconds))
        self._runner = runner

    @property
    def domain(self) -> str:
        return f"gui/{os.getuid()}"

    @property
    def service_target(self) -> str:
        return f"{self.domain}/{LAUNCH_AGENT_LABEL}"

    def _run(self, arguments: list[str], timeout: int = 20) -> CommandResult:
        try:
            completed = self._runner(
                arguments,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CommandResult(1, "", type(exc).__name__)
        return CommandResult(
            int(completed.returncode), completed.stdout or "", completed.stderr or ""
        )

    def _plist(self) -> dict[str, Any]:
        return {
            "Label": LAUNCH_AGENT_LABEL,
            "ProgramArguments": [
                str(self.executable),
                "--config",
                str(self.config_path),
                "run-once",
            ],
            "RunAtLoad": True,
            "StartInterval": self.poll_interval,
            "ProcessType": "Background",
            "LowPriorityIO": True,
            "ThrottleInterval": 10,
            "StandardOutPath": str(self.paths.logs / "agent.stdout.log"),
            "StandardErrorPath": str(self.paths.logs / "agent.stderr.log"),
            "EnvironmentVariables": {
                "PYTHONUNBUFFERED": "1",
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            },
        }

    def install(self, load: bool = True) -> dict[str, Any]:
        if platform.system() != "Darwin":
            raise RuntimeError("LaunchAgent installation requires macOS")
        self.executable = validate_agent_executable(self.executable)
        if not self.config_path.is_file():
            raise ValueError(f"Agent config is missing: {self.config_path}")
        ensure_private_dir(self.paths.root)
        ensure_private_dir(self.paths.logs)
        launch_agents = self.paths.launch_agent.parent
        if launch_agents.is_symlink():
            raise ValueError(
                f"Refusing symbolic-link LaunchAgents directory: {launch_agents}"
            )
        launch_agents.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = launch_agents.stat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"LaunchAgents path is not a directory: {launch_agents}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ValueError("LaunchAgents directory is not owned by the current user")
        payload = plistlib.dumps(self._plist(), fmt=plistlib.FMT_XML).decode("utf-8")
        atomic_write_text(self.paths.launch_agent, payload)
        self.paths.launch_agent.chmod(0o600)

        loaded = False
        detail = "plist installed; not loaded"
        if load:
            self._run(["/bin/launchctl", "bootout", self.service_target])
            result = self._run(
                [
                    "/bin/launchctl",
                    "bootstrap",
                    self.domain,
                    str(self.paths.launch_agent),
                ]
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip() or "launchctl failed"
                raise RuntimeError(f"Could not bootstrap LaunchAgent: {detail}")
            self._run(["/bin/launchctl", "kickstart", "-k", self.service_target])
            loaded = True
            detail = "LaunchAgent installed and loaded"
        return {
            "label": LAUNCH_AGENT_LABEL,
            "plist": str(self.paths.launch_agent),
            "loaded": loaded,
            "detail": detail,
        }

    def uninstall(self) -> dict[str, Any]:
        bootout = self._run(["/bin/launchctl", "bootout", self.service_target])
        if bootout.returncode != 0:
            detail = (bootout.stderr or bootout.stdout).strip() or "launchctl failed"
            raise RuntimeError(f"Could not bootout LaunchAgent: {detail}")
        confirmation = self._run(["/bin/launchctl", "print", self.service_target])
        if confirmation.returncode == 0:
            raise RuntimeError("LaunchAgent is still loaded after bootout")
        removed = False
        if self.paths.launch_agent.exists():
            if self.paths.launch_agent.is_symlink():
                raise ValueError("Refusing symbolic-link LaunchAgent plist")
            self.paths.launch_agent.unlink()
            removed = True
        return {"label": LAUNCH_AGENT_LABEL, "removed": removed, "stopped": True}

    def status(self) -> dict[str, Any]:
        result = self._run(["/bin/launchctl", "print", self.service_target])
        return {
            "label": LAUNCH_AGENT_LABEL,
            "installed": self.paths.launch_agent.is_file(),
            "loaded": result.returncode == 0,
            "paused": self.paths.pause_marker.is_file(),
            "kill_switch": self.paths.kill_switch.is_file(),
            "mode_file": str(self.config_path),
        }


def _write_control_marker(path: Path, value: str) -> None:
    ensure_private_dir(path.parent)
    if path.is_symlink():
        raise ValueError(f"Refusing symbolic-link control marker: {path}")
    atomic_write_text(path, value + "\n")


def pause(paths: AgentPaths) -> dict[str, Any]:
    _write_control_marker(paths.pause_marker, "paused-by-user")
    return {"paused": True, "kill_switch": paths.kill_switch.is_file()}


def resume(paths: AgentPaths) -> dict[str, Any]:
    if paths.kill_switch.is_file():
        raise RuntimeError("Kill switch is active; clear it explicitly before resume")
    paths.pause_marker.unlink(missing_ok=True)
    return {"paused": False, "kill_switch": False}


def set_kill_switch(paths: AgentPaths, enabled: bool) -> dict[str, Any]:
    if enabled:
        _write_control_marker(paths.kill_switch, "emergency-stop")
        _write_control_marker(paths.pause_marker, "kill-switch")
    else:
        paths.kill_switch.unlink(missing_ok=True)
    return {
        "kill_switch": paths.kill_switch.is_file(),
        "paused": paths.pause_marker.is_file(),
    }


def _permission_mode(path: Path) -> Optional[str]:
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))
    except OSError:
        return None


def doctor(config: AgentConfig, config_path: Path) -> dict[str, Any]:
    """Run non-mutating readiness checks without reading chats or calling a model."""
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str, *, required: bool = True) -> None:
        checks.append(
            {
                "name": name,
                "ok": bool(ok),
                "required": required,
                "detail": detail,
            }
        )

    add("macos", platform.system() == "Darwin", platform.platform())
    add(
        "python",
        sys.version_info >= (3, 10),
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    add(
        "config_permissions",
        _permission_mode(config_path) == "0o600",
        _permission_mode(config_path) or "missing",
    )
    add(
        "runtime_mode",
        config.mode in {"observe", "shadow", "approve", "autopilot"},
        config.mode,
    )
    add(
        "real_send_disabled",
        not config.sender.real_send_enabled,
        str(config.sender.real_send_enabled).lower(),
    )
    add(
        "wechat_app",
        Path("/Applications/WeChat.app").is_dir(),
        "/Applications/WeChat.app",
    )
    if config.reader.backend == "sqlcipher":
        add(
            "sqlcipher",
            config.reader.sqlcipher_path.is_file(),
            str(config.reader.sqlcipher_path),
        )
    db_dir = config.reader.db_dir
    readable = bool(db_dir and db_dir.is_dir() and os.access(db_dir, os.R_OK))
    add("database_directory", readable, str(db_dir or "not configured"))
    osascript = shutil.which("osascript")
    accessibility = False
    if osascript and platform.system() == "Darwin":
        try:
            result = subprocess.run(
                [
                    osascript,
                    "-e",
                    'tell application "System Events" to get UI elements enabled',
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            accessibility = result.returncode == 0 and "true" in result.stdout.lower()
        except (OSError, subprocess.TimeoutExpired):
            accessibility = False
    accessibility_required = config.mode in {"approve", "autopilot"}
    add(
        "accessibility",
        accessibility,
        "granted" if accessibility else "not granted; shadow remains available",
        required=accessibility_required,
    )
    add(
        "kill_switch_clear",
        not config.paths.kill_switch.exists(),
        "clear" if not config.paths.kill_switch.exists() else "ACTIVE",
    )
    return {
        "schema": "ginger_agent_doctor_v2",
        "ready": all(item["ok"] for item in checks if item["required"]),
        "checks": checks,
        "network_calls": 0,
        "model_calls": 0,
        "send_actions": 0,
    }
