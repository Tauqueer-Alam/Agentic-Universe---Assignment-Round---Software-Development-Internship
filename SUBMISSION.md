# Assignment A Submission

## Run

Install the dependency with `python -m pip install -r requirements.txt`, then ingest drops in delivery order:

```powershell
python pipeline.py ingest data/drop_1
python pipeline.py ingest data/drop_2
python pipeline.py report --out reports
```

The SQLite database defaults to `ledger.sqlite3`. Its adjacent `.key` file is required to decrypt the stored lead PII; both are local runtime artifacts and are excluded from Git. Use a fresh database and key when starting an independent run.

## Data model and decisions

- `leads` has a unique `(workflow_id, phone_hash)` identity. The phone digest is HMAC-SHA256 with a derived key; the canonical phone and schema-marked PII are AES-256-GCM encrypted. Non-PII attributes are stored as JSON.
- `events` is the append-only interaction ledger with unique event IDs. Immutable fact columns are protected by SQLite triggers. Linkage state (`lead_id` and `status`) is mutable derived metadata so earlier orphans can be resolved when later lead drops arrive. Phone values are never stored in event rows.
- Rejections contain only workflow, batch, row, and reason. Source file digests make exact file re-ingestion a no-op; changed content at an already-ingested path is rejected so users can rebuild into a fresh database instead of silently double-counting.
- File processing is deterministic: lead CSVs are ordered by workflow and filename, then event files by filename. Duplicate lead fields update only when the new normalized value is non-null; defaults are applied only for reporting after merge.
- Naive timestamps are interpreted as IST. Reports use the initiated call's IST date and timestamp. Effective disposition prefers the latest override; absent overrides, it uses the latest set event.
- A malformed event is one with invalid JSON, a missing/blank event ID, or missing/unparseable workflow, event type, or timestamp. Orphans are retained and counted only while unresolved. Unknown dispositions are counted only after an event links to a lead.
- Events with the same timestamp are ordered by event ID for deterministic disposition selection. If multiple input columns map to one field, the rightmost non-empty mapped value wins.

## Tests and operational note

Run `python -m unittest discover -s tests -v`. For a production deployment handling 100k leads/day, schedule each delivery as an idempotent job, validate checksums and row-quality thresholds before publishing reports, retain immutable source drops, alert on failed jobs and quality-count deltas, and backfill by replaying ordered drops into a new database/key before atomically switching report consumers.