from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from pipeline import (
    connect_database,
    effective_disposition,
    event_is_unknown,
    ingest_drop,
    lead_bucket,
    normalize_phone,
    parse_date,
    report,
)


class NormalizationTests(unittest.TestCase):
    def test_phone_formats_and_invalid_values(self) -> None:
        for value in ("9876543210", "+91 98765 43210", "0-9876543210", "91-98765-43210"):
            with self.subTest(value=value):
                self.assertEqual(normalize_phone(value), "+919876543210")
        self.assertIsNone(normalize_phone("022-2345-6789"))
        self.assertIsNone(normalize_phone("5876543210"))

    def test_day_first_dates_and_impossible_date(self) -> None:
        self.assertEqual(parse_date("01-Dec-2026"), "2026-12-01")
        self.assertEqual(parse_date("03/10/2026"), "2026-10-03")
        self.assertIsNone(parse_date("31/02/2026"))


class DerivedFactTests(unittest.TestCase):
    def test_disposition_without_catalogued_code_is_unknown(self) -> None:
        self.assertTrue(event_is_unknown("motor_renewal", "disposition.set", {}))
        self.assertFalse(event_is_unknown("motor_renewal", "call.connected", {}))

    def test_override_precedes_latest_set(self) -> None:
        events = [
            {"event_id": "1", "event_type": "disposition.set", "occurred_at_utc": "2026-01-01T10:00:00+00:00", "payload": {"disposition_code": "renewed"}},
            {"event_id": "2", "event_type": "disposition.override", "occurred_at_utc": "2026-01-01T09:00:00+00:00", "payload": {"disposition_code": "not_interested"}},
        ]
        self.assertEqual(effective_disposition(events), "not_interested")

    def test_bucket_priority_and_all_failed_rule(self) -> None:
        self.assertEqual(lead_bucket([], {}), "yet_to_reach_out")
        calls = [{"effective_disposition": "renewed", "telephony_failed": True}]
        self.assertEqual(lead_bucket(calls, {"renewed": True}), "completed")
        calls = [{"effective_disposition": None, "telephony_failed": True}]
        self.assertEqual(lead_bucket(calls, {}), "in_progress_telephony_failed")
        calls.append({"effective_disposition": None, "telephony_failed": False})
        self.assertEqual(lead_bucket(calls, {}), "in_progress_dialed")


class PipelineIntegrationTests(unittest.TestCase):
    def test_orphan_backfill_idempotency_reports_and_pii_protection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            drop_one = root / "drop_1"
            drop_two = root / "drop_2"
            (drop_one / "events").mkdir(parents=True)
            (drop_two / "leads" / "motor_renewal").mkdir(parents=True)
            events_path = drop_one / "events" / "events_0001.jsonl"
            events = [
                {"event_id": "evt-start", "event_type": "call.initiated", "workflow_id": "motor_renewal", "call_id": "call-1", "occurred_at": "2026-10-03T10:00:00", "phone": "9876543210", "payload": {}},
                {"event_id": "evt-connect", "event_type": "call.connected", "workflow_id": "motor_renewal", "call_id": "call-1", "occurred_at": "2026-10-03T10:00:10+05:30", "phone": "+91 98765 43210", "payload": {}},
                {"event_id": "evt-set", "event_type": "disposition.set", "workflow_id": "motor_renewal", "call_id": "call-1", "occurred_at": "2026-10-03T10:01:00Z", "phone": "09876543210", "payload": {"disposition_code": "renewed"}},
            ]
            events_path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
            lead_path = drop_two / "leads" / "motor_renewal" / "batch_003.csv"
            with lead_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["Insured Name", "Policy No", "Mobile No", "Expiry Date", "Premium", "Language"])
                writer.writerow(["Test Person", "MOT/1", "9876543210", "01-Dec-2026", "Rs. 1,000", "HI"])

            database = root / "ledger.sqlite3"
            connection, key = connect_database(database)
            try:
                ingest_drop(connection, key, drop_one)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM events WHERE status='orphan'").fetchone()[0], 3)
                ingest_drop(connection, key, drop_two)
                counters_before = connection.execute("SELECT name, value FROM counters ORDER BY name").fetchall()
                ingest_drop(connection, key, drop_one)
                self.assertEqual(counters_before, connection.execute("SELECT name, value FROM counters ORDER BY name").fetchall())
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM events WHERE status='linked'").fetchone()[0], 3)
                output = root / "reports"
                report(connection, key, output)
            finally:
                connection.close()

            quality = json.loads((output / "data_quality.json").read_text(encoding="utf-8"))
            self.assertEqual(quality["orphan_events"], 0)
            with (output / "lead_report.csv").open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["phone_masked"], "+91******3210")
            self.assertEqual(row["bucket"], "completed")
            self.assertEqual(row["ever_success"], "true")
            database_bytes = database.read_bytes()
            self.assertNotIn(b"Test Person", database_bytes)
            self.assertNotIn(b"9876543210", database_bytes)


if __name__ == "__main__":
    unittest.main()