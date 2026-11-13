# Interaction Ledger & Reporting Pipeline

Python and SQLite implementation of Assignment A. It ingests workflow lead CSVs and call-event JSONL drops, encrypts lead PII at rest, and writes the five contracted reports.

## Run

Install the dependency and ingest drops in delivery order:

```powershell
python -m pip install -r requirements.txt
python pipeline.py ingest data/drop_1
python pipeline.py ingest data/drop_2
python pipeline.py report --out reports
```

Use `--db path/to/ledger.sqlite3` with either command to select another database. Keep the adjacent `.key` file alongside the database; it is required to decrypt PII. See [SUBMISSION.md](SUBMISSION.md) for storage decisions and operating notes. Run tests with `python -m unittest discover -s tests -v`.