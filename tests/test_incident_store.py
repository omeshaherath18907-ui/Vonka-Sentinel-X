from types import SimpleNamespace

import pytest

from app.services.incident_store import IncidentStore


def sample_alert():
    return SimpleNamespace(
        timestamp="2026-10-25T12:00:00+00:00",
        rule_id="TRAFFIC_PPS_CRITICAL",
        severity="CRITICAL",
        title="Very high packet rate",
        reason="Synthetic test alert.",
        observed_value=2000,
        threshold=1500,
    )


def test_alert_persists_after_reopening_store(tmp_path):
    database = tmp_path / "sentinel.db"
    alert = sample_alert()

    first_store = IncidentStore(database)
    assert first_store.save_alert(alert, "test-alert-1") is True

    reopened_store = IncidentStore(database)
    records = reopened_store.get_recent()

    assert len(records) == 1
    assert records[0]["incident_key"] == "test-alert-1"
    assert records[0]["severity"] == "CRITICAL"
    assert records[0]["observed_value"] == "2000"
    assert records[0]["threshold"] == "1500"


def test_duplicate_alert_is_not_inserted_twice(tmp_path):
    store = IncidentStore(tmp_path / "sentinel.db")
    alert = sample_alert()

    assert store.save_alert(alert, "same-alert") is True
    assert store.save_alert(alert, "same-alert") is False
    assert store.count() == 1


def test_status_and_notes_are_persisted(tmp_path):
    database = tmp_path / "sentinel.db"
    store = IncidentStore(database)
    store.save_alert(sample_alert(), "test-alert-2")

    assert store.update_metadata(
        "test-alert-2", "Investigating", "Reviewing traffic pattern."
    )

    reopened_store = IncidentStore(database)
    record = reopened_store.get_recent()[0]

    assert record["status"] == "Investigating"
    assert record["notes"] == "Reviewing traffic pattern."


def test_invalid_status_is_rejected(tmp_path):
    store = IncidentStore(tmp_path / "sentinel.db")

    with pytest.raises(ValueError):
        store.update_metadata("missing", "Unknown", "test")


def test_recent_limit_must_be_positive(tmp_path):
    store = IncidentStore(tmp_path / "sentinel.db")

    with pytest.raises(ValueError):
        store.get_recent(0)
