from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from backend.history_store import HistoryStore


def _entry(timestamp: str, target: str, result_value: int) -> dict:
    return {
        "timestamp": timestamp,
        "target": target,
        "result": {"value": result_value},
    }


def test_history_store_saves_and_loads_entries_correctly(tmp_path: Path) -> None:
    store = HistoryStore(db_path=str(tmp_path / "history.db"))
    saved = _entry("2026-01-01T10:00:00", "example.com", 1)

    store.save_entry(saved)
    loaded = store.load_entries()

    assert len(loaded) == 1
    assert loaded[0] == saved


def test_load_entries_orders_by_timestamp_desc(tmp_path: Path) -> None:
    store = HistoryStore(db_path=str(tmp_path / "history.db"))
    oldest = _entry("2026-01-01T09:00:00", "old.example", 1)
    newest = _entry("2026-01-01T11:00:00", "new.example", 2)
    middle = _entry("2026-01-01T10:00:00", "mid.example", 3)

    store.save_entry(oldest)
    store.save_entry(newest)
    store.save_entry(middle)

    loaded = store.load_entries()

    assert [item["timestamp"] for item in loaded] == [
        "2026-01-01T11:00:00",
        "2026-01-01T10:00:00",
        "2026-01-01T09:00:00",
    ]


def test_load_entries_limit_parameter(tmp_path: Path) -> None:
    store = HistoryStore(db_path=str(tmp_path / "history.db"))

    for i in range(5):
        store.save_entry(
            _entry(
                f"2026-01-01T10:00:0{i}",
                f"target-{i}.example",
                i,
            )
        )

    limited = store.load_entries(limit=2)

    assert len(limited) == 2
    assert [item["timestamp"] for item in limited] == [
        "2026-01-01T10:00:04",
        "2026-01-01T10:00:03",
    ]


def test_import_json_legacy_handles_empty_file(tmp_path: Path) -> None:
    store = HistoryStore(db_path=str(tmp_path / "history.db"))
    legacy_path = tmp_path / "scan_history.json"
    legacy_path.write_text("[]", encoding="utf-8")

    imported = store.import_json_legacy(str(legacy_path))

    assert imported == 0
    assert store.load_entries() == []


def test_import_json_legacy_skips_malformed_entries(tmp_path: Path) -> None:
    store = HistoryStore(db_path=str(tmp_path / "history.db"))
    legacy_path = tmp_path / "scan_history.json"
    payload = [
        {"timestamp": "2026-01-01T09:00:00", "target": "a.example", "result": {"ok": True}},
        {"target": "missing-time.example", "result": {"ok": False}},
        "not-a-dict",
        {"date": "2026-01-01T08:00:00", "foo": "bar"},
    ]
    legacy_path.write_text(json.dumps(payload), encoding="utf-8")

    imported = store.import_json_legacy(str(legacy_path))
    loaded = store.load_entries()

    assert imported == 2
    assert len(loaded) == 2
    assert [item["timestamp"] for item in loaded] == [
        "2026-01-01T09:00:00",
        "2026-01-01T08:00:00",
    ]
    assert loaded[1]["target"] == "Unknown"


def test_history_store_thread_safety_concurrent_saves(tmp_path: Path) -> None:
    store = HistoryStore(db_path=str(tmp_path / "history.db"))
    total = 40

    def save_one(i: int) -> None:
        store.save_entry(
            _entry(
                f"2026-01-01T12:00:{i:02d}",
                f"concurrent-{i}.example",
                i,
            )
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(save_one, i) for i in range(total)]
        for future in futures:
            future.result()

    loaded = store.load_entries()

    assert len(loaded) == total
    targets = {item["target"] for item in loaded}
    assert len(targets) == total
