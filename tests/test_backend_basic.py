import json

from backend import ShieldEyeBackend

def test_backend_can_be_initialized():
    backend = ShieldEyeBackend()
    assert backend is not None

def test_history_roundtrip_tmp(tmp_path):
    backend = ShieldEyeBackend()
    history_file = tmp_path / "history.json"
    backend.save_scan_to_history([], [], history_file=str(history_file))
    history = backend.load_history(history_file=str(history_file))
    assert isinstance(history, list)
