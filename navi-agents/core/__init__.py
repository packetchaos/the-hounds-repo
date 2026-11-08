"""Navi Agents — shared core (db access, agents, registry, service layer)."""
__version__ = "1.0.0"

# Apply the Settings-page config store (hounds.config.json) before any module reads
# os.environ — core.llm binds its provider/model at import. See core/config_store.py.
try:
    from . import config_store as _config_store
    _config_store.bootstrap()
except Exception as _e:  # never block startup on a bad config file
    print("hounds config store:", _e)
