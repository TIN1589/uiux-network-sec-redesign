import os, sys, importlib.util

_root_app_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'app.py')
if os.path.exists(_root_app_path):
    _spec = importlib.util.spec_from_file_location('_root_app', _root_app_path)
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules['_root_app'] = _mod
    _spec.loader.exec_module(_mod)
    app = getattr(_mod, 'app', None)
    AUDIT_LOGS = getattr(_mod, 'AUDIT_LOGS', [])
    alerts_store = getattr(_mod, 'alerts_store', [])
    deduplicate_composite_alerts = getattr(_mod, 'deduplicate_composite_alerts', None)
