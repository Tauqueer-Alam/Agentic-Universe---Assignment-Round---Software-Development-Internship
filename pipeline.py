from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parent
SCHEMA_DIR = ROOT / "assignment-a-data" / "schemas"
IST = timezone(timedelta(hours=5, minutes=30))
COUNTER_NAMES = (
    "lead_rows_total",
    "lead_rows_rejected",
    "duplicate_lead_rows_merged",
    "field_warnings",
    "events_total",
    "malformed_events",
    "duplicate_events_dropped",
)
QUALITY_ORDER = (
    "lead_rows_total",
    "lead_rows_rejected",
    "rejections_by_reason",
    "duplicate_lead_rows_merged",
    "field_warnings",
    "events_total",
    "malformed_events",
    "duplicate_events_dropped",
    "orphan_events",
    "unknown_disposition_events",
)


def load_schemas() -> dict[str, dict[str, Any]]:
    schemas = {}
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        schemas[schema["workflow_id"]] = schema
    return schemas


def load_dispositions() -> dict[str, dict[str, dict[str, bool]]]:
    catalog: dict[str, dict[str, dict[str, bool]]] = defaultdict(dict)
    with (SCHEMA_DIR / "dispositions.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            catalog[row["workflow_id"]][row["code"]] = {
                "is_terminal": row["is_terminal"].lower() == "true",
                "is_success": row["is_success"].lower() == "true",
            }
    return catalog


SCHEMAS = load_schemas()
DISPOSITIONS = load_dispositions()


def normalize_phone(value: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) != 10 or digits[0] not in "6789":
        return None
    return "+91" + digits


def parse_date(value: str) -> str | None:
    for pattern in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d-%b-%Y"):
        try:
            return datetime.strptime(value, pattern).date().isoformat()
        except ValueError:
            continue
    return None


def parse_decimal(value: str) -> str | None:
    cleaned = re.sub(r"^(?:₹|Rs\.?|INR)\s*", "", value, flags=re.IGNORECASE).strip()
    if not re.fullmatch(r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?", cleaned):
        return None
    try:
        amount = Decimal(cleaned.replace(",", ""))
    except InvalidOperation:
        return None
    if not amount.is_finite() or amount < 0:
        return None
    return str(amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def parse_field(field: dict[str, Any], value: str) -> Any | None:
    if value == "":
        return None
    kind = field["type"]
    if kind == "string":
        return value
    if kind == "phone":
        return normalize_phone(value)
    if kind == "date":
        return parse_date(value)
    if kind == "decimal":
        return parse_decimal(value)
    if kind == "enum":
        choice = value.lower()
        return choice if choice in field["values"] else None
    raise ValueError(f"Unsupported field type: {kind}")


def normalize_header(value: str) -> str:
    return re.sub(r"[_\s]+", " ", value.strip().lower())


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=IST)
    return parsed.astimezone(timezone.utc)


def event_timestamp_key(value: str) -> str:
    return parse_timestamp(value).isoformat(timespec="microseconds")


def encrypt_value(key: bytes, context: str, value: str) -> str:
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(key).encrypt(nonce, value.encode("utf-8"), context.encode("utf-8"))
    return base64.urlsafe_b64encode(nonce + cipher).decode("ascii")


def decrypt_value(key: bytes, context: str, value: str) -> str:
    packed = base64.urlsafe_b64decode(value.encode("ascii"))
    return AESGCM(key).decrypt(packed[:12], packed[12:], context.encode("utf-8")).decode("utf-8")


def lead_bucket(calls: list[dict[str, Any]], terminal_by_code: dict[str, bool]) -> str:
    if not calls:
        return "yet_to_reach_out"
    if any(call["effective_disposition"] and terminal_by_code.get(call["effective_disposition"], False) for call in calls):
        return "completed"
    if all(call["telephony_failed"] for call in calls):
        return "in_progress_telephony_failed"
    return "in_progress_dialed"


def effective_disposition(call_events: list[dict[str, Any]]) -> str | None:
    overrides = [event for event in call_events if event["event_type"] == "disposition.override"]
    candidates = overrides or [event for event in call_events if event["event_type"] == "disposition.set"]
    if not candidates:
        return None
    latest = max(candidates, key=lambda event: (event["occurred_at_utc"], event["event_id"]))
    return (latest["payload"] or {}).get("disposition_code")


def connect_database(path: Path) -> tuple[sqlite3.Connection, bytes]:
    path.parent.mkdir(parents=True, exist_ok=True)
    key_path = path.with_suffix(path.suffix + ".key")
    if key_path.exists():
        key = key_path.read_bytes()
        if len(key) != 32:
            raise ValueError(f"Invalid encryption key file: {key_path}")
    else:
        key = secrets.token_bytes(32)
        try:
            with key_path.open("xb") as handle:
                handle.write(key)
        except FileExistsError:
            key = key_path.read_bytes()
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS counters (
            name TEXT PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS source_files (
            file_key TEXT PRIMARY KEY,
            digest TEXT NOT NULL,
            kind TEXT NOT NULL,
            rows_counted INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS leads (
            lead_id INTEGER PRIMARY KEY,
            workflow_id TEXT NOT NULL,
            batch_id TEXT NOT NULL,
            phone_hash TEXT NOT NULL,
            phone_cipher TEXT NOT NULL,
            pii_cipher TEXT NOT NULL,
            attributes_json TEXT NOT NULL,
            UNIQUE(workflow_id, phone_hash)
        );
        CREATE INDEX IF NOT EXISTS leads_phone_lookup ON leads(workflow_id, phone_hash);
        CREATE TABLE IF NOT EXISTS rejections (
            workflow_id TEXT NOT NULL,
            batch_id TEXT NOT NULL,
            row_number INTEGER NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY(workflow_id, batch_id, row_number)
        );
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            workflow_id TEXT NOT NULL,
            call_id TEXT,
            occurred_at_utc TEXT NOT NULL,
            phone_hash TEXT,
            lead_id INTEGER REFERENCES leads(lead_id),
            payload_json TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'orphan'
        );
        CREATE INDEX IF NOT EXISTS events_call_lookup ON events(workflow_id, call_id, lead_id);
        CREATE INDEX IF NOT EXISTS events_phone_lookup ON events(workflow_id, phone_hash, lead_id);
        CREATE TRIGGER IF NOT EXISTS events_facts_are_immutable
        BEFORE UPDATE OF event_id, event_type, workflow_id, call_id, occurred_at_utc,
                         phone_hash, payload_json ON events
        BEGIN
            SELECT RAISE(ABORT, 'ledger event facts are immutable');
        END;
        CREATE TRIGGER IF NOT EXISTS events_cannot_be_deleted
        BEFORE DELETE ON events
        BEGIN
            SELECT RAISE(ABORT, 'ledger events cannot be deleted');
        END;
        """
    )
    connection.executemany("INSERT OR IGNORE INTO counters(name, value) VALUES (?, 0)", ((name,) for name in COUNTER_NAMES))
    return connection, key


def increment(connection: sqlite3.Connection, name: str, amount: int = 1) -> None:
    connection.execute("UPDATE counters SET value = value + ? WHERE name = ?", (amount, name))


def file_metadata(path: Path, drop: Path) -> tuple[str, str, str]:
    content = path.read_bytes()
    key = f"{drop.resolve()}::{path.relative_to(drop).as_posix()}"
    return key, hashlib.sha256(content).hexdigest(), content.decode("utf-8-sig")


def previously_ingested(connection: sqlite3.Connection, file_key: str, digest: str) -> bool:
    row = connection.execute("SELECT digest FROM source_files WHERE file_key = ?", (file_key,)).fetchone()
    if row is None:
        return False
    if row["digest"] != digest:
        raise ValueError(f"Input file changed after ingestion: {file_key}; use a fresh database for a revised drop")
    return True


def field_columns(schema: dict[str, Any], headers: list[str]) -> dict[str, list[int]]:
    lookup = {}
    for field in schema["fields"]:
        for name in [field["name"], *field.get("aliases", [])]:
            lookup[normalize_header(name)] = field["name"]
    mapping: dict[str, list[int]] = defaultdict(list)
    for index, header in enumerate(headers):
        field_name = lookup.get(normalize_header(header))
        if field_name:
            mapping[field_name].append(index)
    return mapping


def row_values(schema: dict[str, Any], raw: list[str], mapping: dict[str, list[int]]) -> tuple[dict[str, Any], str | None, int]:
    parsed: dict[str, Any] = {}
    warnings = 0
    failure = None
    for field in schema["fields"]:
        name = field["name"]
        indices = mapping.get(name, [])
        value = ""
        for index in reversed(indices):
            if index < len(raw) and raw[index].strip():
                value = raw[index].strip()
                break
        if not value:
            parsed[name] = None
            if field.get("required"):
                failure = f"missing_required:{name}"
                break
            continue
        normalized = parse_field(field, value)
        if normalized is None:
            if name == "phone":
                failure = "invalid_phone"
                break
            if field.get("required"):
                failure = f"invalid_required:{name}"
                break
            warnings += 1
        parsed[name] = normalized
    return parsed, failure, warnings


def ingest_lead_file(connection: sqlite3.Connection, key: bytes, path: Path, drop: Path) -> None:
    workflow_id = path.parent.name
    if workflow_id not in SCHEMAS:
        raise ValueError(f"No lead schema for workflow: {workflow_id}")
    schema = SCHEMAS[workflow_id]
    file_key, digest, text = file_metadata(path, drop)
    if previously_ingested(connection, file_key, digest):
        return
    rows_counted = 0
    with connection:
        reader = csv.reader(io.StringIO(text, newline=""))
        try:
            headers = next(reader)
        except StopIteration:
            connection.execute("INSERT INTO source_files(file_key, digest, kind, rows_counted) VALUES (?, ?, 'lead', 0)", (file_key, digest))
            return
        mapping = field_columns(schema, headers)
        for row in reader:
            if not any(cell.strip() for cell in row):
                continue
            rows_counted += 1
            increment(connection, "lead_rows_total")
            parsed, reason, warnings = row_values(schema, row, mapping)
            if reason:
                increment(connection, "lead_rows_rejected")
                connection.execute(
                    "INSERT INTO rejections(workflow_id, batch_id, row_number, reason) VALUES (?, ?, ?, ?)",
                    (workflow_id, path.stem, rows_counted, reason),
                )
                continue
            increment(connection, "field_warnings", warnings)
            phone = parsed["phone"]
            phone_hash = hmac.new(hmac.new(key, b"phone-lookup", hashlib.sha256).digest(), phone.encode(), hashlib.sha256).hexdigest()
            pii_values = {field["name"]: parsed.get(field["name"]) for field in schema["fields"] if field.get("pii") and field["name"] != "phone"}
            attributes = {field["name"]: parsed.get(field["name"]) for field in schema["fields"] if not field.get("pii") and field["name"] != "phone"}
            existing = connection.execute(
                "SELECT lead_id, pii_cipher, attributes_json FROM leads WHERE workflow_id = ? AND phone_hash = ?",
                (workflow_id, phone_hash),
            ).fetchone()
            if existing:
                increment(connection, "duplicate_lead_rows_merged")
                merged_pii = json.loads(decrypt_value(key, f"lead:{workflow_id}:pii", existing["pii_cipher"]))
                merged_attributes = json.loads(existing["attributes_json"])
                for name, value in pii_values.items():
                    if value is not None:
                        merged_pii[name] = value
                for name, value in attributes.items():
                    if value is not None:
                        merged_attributes[name] = value
                connection.execute(
                    "UPDATE leads SET pii_cipher = ?, attributes_json = ? WHERE lead_id = ?",
                    (
                        encrypt_value(key, f"lead:{workflow_id}:pii", json.dumps(merged_pii, ensure_ascii=False)),
                        json.dumps(merged_attributes, ensure_ascii=False),
                        existing["lead_id"],
                    ),
                )
            else:
                connection.execute(
                    """INSERT INTO leads(workflow_id, batch_id, phone_hash, phone_cipher, pii_cipher, attributes_json)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        workflow_id,
                        path.stem,
                        phone_hash,
                        encrypt_value(key, f"lead:{workflow_id}:phone", phone),
                        encrypt_value(key, f"lead:{workflow_id}:pii", json.dumps(pii_values, ensure_ascii=False)),
                        json.dumps(attributes, ensure_ascii=False),
                    ),
                )
        connection.execute(
            "INSERT INTO source_files(file_key, digest, kind, rows_counted) VALUES (?, ?, 'lead', ?)",
            (file_key, digest, rows_counted),
        )


def event_disposition_code(event_type: str, payload: dict[str, Any]) -> str | None:
    if event_type.startswith("disposition."):
        code = payload.get("disposition_code")
        return code if isinstance(code, str) else None
    return None


def event_is_unknown(workflow_id: str, event_type: str, payload: dict[str, Any]) -> bool:
    code = event_disposition_code(event_type, payload)
    return event_type.startswith("disposition.") and code not in DISPOSITIONS.get(workflow_id, {})


def reconcile_events(connection: sqlite3.Connection) -> None:
    pending = connection.execute("SELECT * FROM events WHERE lead_id IS NULL").fetchall()
    for event in pending:
        lead_id = None
        if event["event_type"] == "disposition.override":
            match = connection.execute(
                "SELECT lead_id FROM events WHERE workflow_id = ? AND call_id = ? AND lead_id IS NOT NULL ORDER BY event_id LIMIT 1",
                (event["workflow_id"], event["call_id"]),
            ).fetchone()
            if match:
                lead_id = match["lead_id"]
        elif event["phone_hash"]:
            match = connection.execute(
                "SELECT lead_id FROM leads WHERE workflow_id = ? AND phone_hash = ?",
                (event["workflow_id"], event["phone_hash"]),
            ).fetchone()
            if match:
                lead_id = match["lead_id"]
        if lead_id is None:
            continue
        payload = json.loads(event["payload_json"])
        status = "unknown_disposition" if event_is_unknown(event["workflow_id"], event["event_type"], payload) else "linked"
        connection.execute("UPDATE events SET lead_id = ?, status = ? WHERE event_id = ?", (lead_id, status, event["event_id"]))
    overrides = connection.execute(
        "SELECT event_id, workflow_id, call_id FROM events WHERE event_type = 'disposition.override' AND lead_id IS NULL"
    ).fetchall()
    for event in overrides:
        match = connection.execute(
            "SELECT lead_id FROM events WHERE workflow_id = ? AND call_id = ? AND lead_id IS NOT NULL ORDER BY event_id LIMIT 1",
            (event["workflow_id"], event["call_id"]),
        ).fetchone()
        if match:
            payload_row = connection.execute("SELECT payload_json FROM events WHERE event_id = ?", (event["event_id"],)).fetchone()
            payload = json.loads(payload_row["payload_json"])
            status = "unknown_disposition" if event_is_unknown(event["workflow_id"], "disposition.override", payload) else "linked"
            connection.execute("UPDATE events SET lead_id = ?, status = ? WHERE event_id = ?", (match["lead_id"], status, event["event_id"]))


def phone_digest(key: bytes, phone: str) -> str:
    derived = hmac.new(key, b"phone-lookup", hashlib.sha256).digest()
    return hmac.new(derived, phone.encode(), hashlib.sha256).hexdigest()


def ingest_event_file(connection: sqlite3.Connection, key: bytes, drop: Path, path: Path) -> None:
    file_key, digest, text = file_metadata(path, drop)
    if previously_ingested(connection, file_key, digest):
        return
    nonempty = 0
    with connection:
        for line in text.splitlines():
            if not line.strip():
                continue
            nonempty += 1
            increment(connection, "events_total")
            try:
                event = json.loads(line)
                event_id = event.get("event_id") if isinstance(event, dict) else None
                if not isinstance(event_id, str) or not event_id.strip():
                    raise ValueError("missing event_id")
                workflow_id = event.get("workflow_id")
                event_type = event.get("event_type")
                if not isinstance(workflow_id, str) or not isinstance(event_type, str):
                    raise ValueError("missing event workflow or type")
                occurred_at_utc = event_timestamp_key(event["occurred_at"])
                call_id = event.get("call_id")
                if call_id is not None and not isinstance(call_id, str):
                    call_id = str(call_id)
                raw_phone = event.get("phone")
                canonical_phone = normalize_phone(raw_phone) if isinstance(raw_phone, str) else None
                phone_hash = phone_digest(key, canonical_phone) if canonical_phone else None
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    payload = {}
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                increment(connection, "malformed_events")
                continue
            try:
                connection.execute(
                    """INSERT INTO events(event_id, event_type, workflow_id, call_id, occurred_at_utc,
                       phone_hash, payload_json, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'orphan')""",
                    (event_id, event_type, workflow_id, call_id, occurred_at_utc, phone_hash, json.dumps(payload, ensure_ascii=False)),
                )
            except sqlite3.IntegrityError:
                increment(connection, "duplicate_events_dropped")
        connection.execute(
            "INSERT INTO source_files(file_key, digest, kind, rows_counted) VALUES (?, ?, 'event', ?)",
            (file_key, digest, nonempty),
        )
        reconcile_events(connection)


def ingest_drop(connection: sqlite3.Connection, key: bytes, drop: Path) -> None:
    if not drop.is_dir():
        raise ValueError(f"Drop directory does not exist: {drop}")
    lead_files = sorted((drop / "leads").glob("*/*.csv"), key=lambda path: (path.parent.name, path.name))
    event_files = sorted((drop / "events").glob("*.jsonl"), key=lambda path: path.name)
    for path in lead_files:
        ingest_lead_file(connection, key, path, drop)
    reconcile_events(connection)
    for path in event_files:
        ingest_event_file(connection, key, drop, path)
    reconcile_events(connection)


def event_records(connection: sqlite3.Connection, lead_id: int) -> list[dict[str, Any]]:
    rows = connection.execute(
        "SELECT * FROM events WHERE lead_id = ? AND status = 'linked' ORDER BY occurred_at_utc, event_id", (lead_id,)
    ).fetchall()
    return [
        {
            "event_id": row["event_id"],
            "event_type": row["event_type"],
            "workflow_id": row["workflow_id"],
            "call_id": row["call_id"],
            "occurred_at_utc": row["occurred_at_utc"],
            "payload": json.loads(row["payload_json"]),
        }
        for row in rows
    ]


def call_facts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["call_id"]:
            by_id[event["call_id"]].append(event)
    calls = []
    for call_id, call_events in by_id.items():
        initiated = [event for event in call_events if event["event_type"] == "call.initiated"]
        if not initiated:
            continue
        start = min(initiated, key=lambda event: (event["occurred_at_utc"], event["event_id"]))
        disposition = effective_disposition(call_events)
        calls.append(
            {
                "call_id": call_id,
                "initiated": start["occurred_at_utc"],
                "connected": any(event["event_type"] == "call.connected" for event in call_events),
                "telephony_failed": any(event["event_type"] == "call.telephony_failed" for event in call_events),
                "effective_disposition": disposition if disposition in DISPOSITIONS.get(start["workflow_id"], {}) else None,
            }
        )
    return sorted(calls, key=lambda call: (call["initiated"], call["call_id"]))


def write_csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def report(connection: sqlite3.Connection, key: bytes, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    leads = connection.execute("SELECT * FROM leads ORDER BY workflow_id, lead_id").fetchall()
    batches: dict[tuple[str, str], list[str]] = defaultdict(list)
    lead_rows = []
    daily: dict[tuple[str, str], dict[str, Any]] = {}
    rejections = connection.execute(
        "SELECT workflow_id, batch_id, row_number, reason FROM rejections ORDER BY workflow_id, batch_id, row_number"
    ).fetchall()
    rejection_counts: dict[str, int] = defaultdict(int)
    for rejection in rejections:
        rejection_counts[rejection["reason"]] += 1

    for lead in leads:
        workflow_id = lead["workflow_id"]
        schema = SCHEMAS[workflow_id]
        attrs = json.loads(lead["attributes_json"])
        pii = json.loads(decrypt_value(key, f"lead:{workflow_id}:pii", lead["pii_cipher"]))
        phone = decrypt_value(key, f"lead:{workflow_id}:phone", lead["phone_cipher"])
        reference = next(field["name"] for field in schema["fields"] if field.get("reference"))
        external_ref = attrs.get(reference) or ""
        for field in schema["fields"]:
            if attrs.get(field["name"]) is None and pii.get(field["name"]) is None and "default" in field:
                if field.get("pii"):
                    pii[field["name"]] = field["default"]
                else:
                    attrs[field["name"]] = field["default"]
        calls = call_facts(event_records(connection, lead["lead_id"]))
        disposition_meta = DISPOSITIONS.get(workflow_id, {})
        bucket = lead_bucket(calls, {code: value["is_terminal"] for code, value in disposition_meta.items()})
        batches[(workflow_id, lead["batch_id"])].append(bucket)
        success = any(call["effective_disposition"] and disposition_meta[call["effective_disposition"]]["is_success"] for call in calls)
        current_disposition = next((call["effective_disposition"] for call in reversed(calls) if call["effective_disposition"]), "")
        last_call_at = ""
        if calls:
            last_call_at = datetime.fromisoformat(calls[-1]["initiated"].replace("Z", "+00:00")).astimezone(IST).isoformat(timespec="seconds")
        lead_rows.append(
            [workflow_id, external_ref, lead["batch_id"], "+91******" + phone[-4:], bucket, len(calls),
             sum(call["connected"] for call in calls), last_call_at, current_disposition, str(success).lower()]
        )
        for call in calls:
            call_date = datetime.fromisoformat(call["initiated"].replace("Z", "+00:00")).astimezone(IST).date().isoformat()
            summary = daily.setdefault((workflow_id, call_date), {"total": 0, "connected": 0, "success_leads": set()})
            summary["total"] += 1
            summary["connected"] += int(call["connected"])
            code = call["effective_disposition"]
            if code and disposition_meta[code]["is_success"]:
                summary["success_leads"].add(lead["lead_id"])

    lead_rows.sort(key=lambda row: (row[0], row[1]))
    write_csv(
        output / "lead_report.csv",
        ["workflow_id", "external_ref", "batch_id", "phone_masked", "bucket", "total_calls", "connected_calls", "last_call_at", "current_disposition", "ever_success"],
        lead_rows,
    )
    batch_rows = []
    bucket_order = ("yet_to_reach_out", "in_progress_telephony_failed", "in_progress_dialed", "completed")
    for (workflow_id, batch_id), bucket_list in sorted(batches.items()):
        counts = {bucket: bucket_list.count(bucket) for bucket in bucket_order}
        batch_rows.append([workflow_id, batch_id, len(bucket_list), *(counts[bucket] for bucket in bucket_order)])
    write_csv(
        output / "batch_summary.csv",
        ["workflow_id", "batch_id", "total_leads", "yet_to_reach_out", "in_progress_telephony_failed", "in_progress_dialed", "completed"],
        batch_rows,
    )
    daily_rows = []
    for (workflow_id, call_date), values in sorted(daily.items()):
        daily_rows.append(
            [workflow_id, call_date, values["total"], values["connected"], f"{values['connected'] / values['total']:.4f}", len(values["success_leads"])]
        )
    write_csv(
        output / "daily_overview.csv",
        ["workflow_id", "date", "total_calls", "connected_calls", "connectivity_rate", "success_leads"],
        daily_rows,
    )
    write_csv(
        output / "rejections.csv",
        ["workflow_id", "batch_id", "row_number", "reason"],
        [[row["workflow_id"], row["batch_id"], row["row_number"], row["reason"]] for row in rejections],
    )
    counters = {row["name"]: row["value"] for row in connection.execute("SELECT name, value FROM counters")}
    quality = {
        "lead_rows_total": counters["lead_rows_total"],
        "lead_rows_rejected": counters["lead_rows_rejected"],
        "rejections_by_reason": dict(sorted(rejection_counts.items())),
        "duplicate_lead_rows_merged": counters["duplicate_lead_rows_merged"],
        "field_warnings": counters["field_warnings"],
        "events_total": counters["events_total"],
        "malformed_events": counters["malformed_events"],
        "duplicate_events_dropped": counters["duplicate_events_dropped"],
        "orphan_events": connection.execute("SELECT COUNT(*) FROM events WHERE status = 'orphan'").fetchone()[0],
        "unknown_disposition_events": connection.execute("SELECT COUNT(*) FROM events WHERE status = 'unknown_disposition'").fetchone()[0],
    }
    quality = {name: quality[name] for name in QUALITY_ORDER}
    (output / "data_quality.json").write_text(json.dumps(quality, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest lead drops and call events into an encrypted SQLite ledger.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    ingest_parser = subparsers.add_parser("ingest", help="ingest one data drop")
    ingest_parser.add_argument("drop", type=Path)
    ingest_parser.add_argument("--db", type=Path, default=ROOT / "ledger.sqlite3")
    report_parser = subparsers.add_parser("report", help="write the five report files")
    report_parser.add_argument("--out", type=Path, required=True)
    report_parser.add_argument("--db", type=Path, default=ROOT / "ledger.sqlite3")
    args = parser.parse_args(argv)
    connection, key = connect_database(args.db)
    try:
        if args.command == "ingest":
            ingest_drop(connection, key, args.drop.resolve())
            print(f"Ingested {args.drop}")
        else:
            report(connection, key, args.out)
            print(f"Reports written to {args.out}")
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())