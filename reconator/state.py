from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from .utils import now_iso, read_json, write_json


@dataclass
class ModuleState:
    status: str = "PENDING"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None
    command: Optional[str] = None
    stdout_path: Optional[str] = None
    stderr_path: Optional[str] = None
    error: Optional[str] = None
    artifacts: Dict[str, str] = field(default_factory=dict)


@dataclass
class HostState:
    engagement_name: str
    host: str
    modules: Dict[str, ModuleState] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "engagement_name": self.engagement_name,
            "host": self.host,
            "modules": {
                name: module.__dict__ for name, module in self.modules.items()
            },
        }

    def save(self, path: Path) -> None:
        write_json(path, self.to_dict())

    @classmethod
    def load(cls, path: Path, engagement_name: str, host: str) -> "HostState":
        data = read_json(path)
        if not data:
            return cls(engagement_name=engagement_name, host=host)
        modules = {
            name: ModuleState(**values) for name, values in data.get("modules", {}).items()
        }
        return cls(engagement_name=data.get("engagement_name", engagement_name), host=data.get("host", host), modules=modules)


def init_module_state(state: HostState, name: str) -> ModuleState:
    module = state.modules.get(name)
    if not module:
        module = ModuleState()
        state.modules[name] = module
    return module


def mark_running(module: ModuleState, command: str, stdout_path: Path, stderr_path: Path) -> None:
    module.status = "RUNNING"
    module.started_at = now_iso()
    module.command = command
    module.stdout_path = str(stdout_path)
    module.stderr_path = str(stderr_path)


def mark_finished(module: ModuleState, status: str, exit_code: Optional[int], error: Optional[str] = None) -> None:
    module.status = status
    module.exit_code = exit_code
    module.finished_at = now_iso()
    module.error = error

