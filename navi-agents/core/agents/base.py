"""Agent base class + registry contract.

Every Navi agent subclasses Agent, declares id/name/description, and implements
run(). The registry (core/registry.py) instantiates them; the API exposes
meta() for the status page and run() for execution. Adding a new agent is one
file + one registry line.
"""
import datetime
import traceback


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class Agent:
    id: str = "base"
    name: str = "Agent"
    description: str = ""
    icon: str = "🤖"
    runnable: bool = True

    def __init__(self):
        self.status: str = "ready"      # ready | running | complete | error
        self.last_run: str | None = None
        self.result: dict | None = None
        self.error: str | None = None

    def run(self, db_path: str | None = None, **kwargs) -> dict:
        """Execute the agent against navi.db. Subclasses override _run().
        Extra kwargs are forwarded to _run() to support pipeline hand-offs."""
        self.status = "running"
        self.error = None
        try:
            self.result = self._run(db_path, **kwargs)
            self.status = "complete"
            self.last_run = now_iso()
            return self.result
        except Exception as e:
            self.status = "error"
            self.error = f"{e}"
            traceback.print_exc()
            raise

    def _run(self, db_path: str | None, **kwargs) -> dict:
        raise NotImplementedError

    def meta(self) -> dict:
        return {
            "id": self.id, "name": self.name, "description": self.description,
            "icon": self.icon, "runnable": self.runnable, "status": self.status,
            "last_run": self.last_run, "error": self.error,
            "summary": self.summary(),
        }

    def summary(self) -> dict:
        """Headline numbers for the status card. Overridden per agent."""
        return {}
