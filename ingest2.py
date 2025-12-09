import sqlite3
import re
from datetime import datetime

OLD_DB = "boofuzz-results/help.db"
NEW_DB = "vchat_fuzz_analysis.db"
CSV_FILE = "csv/help_fuzz_log.csv"


# ============================================================
# Create Simplified Schema
# ============================================================
def create_new_schema(conn):
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS fuzz_runs (
        run_id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time TEXT,
        end_time TEXT,
        total_cases INTEGER,
        total_crashes INTEGER
    );

    CREATE TABLE IF NOT EXISTS test_cases (
        case_id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        case_number INTEGER,
        case_name TEXT,
        timestamp TEXT,
        FOREIGN KEY (run_id) REFERENCES fuzz_runs(run_id)
    );

    CREATE TABLE IF NOT EXISTS crashes (
        crash_id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER,
        run_id INTEGER,
        timestamp TEXT,
        crash_reason TEXT,
        FOREIGN KEY (case_id) REFERENCES test_cases(case_id),
        FOREIGN KEY (run_id) REFERENCES fuzz_runs(run_id)
    );

    CREATE TABLE IF NOT EXISTS crash_inputs (
        input_id INTEGER PRIMARY KEY AUTOINCREMENT,
        crash_id INTEGER,
        payload BLOB,
        payload_size INTEGER,
        FOREIGN KEY (crash_id) REFERENCES crashes(crash_id)
    );
    """)

    conn.commit()


# ============================================================
# Load OLD Tables
# ============================================================
def load_old_tables():
    conn = sqlite3.connect(OLD_DB)
    cur = conn.cursor()

    cases = cur.execute("SELECT name, number, timestamp FROM cases").fetchall()
    steps = cur.execute("SELECT test_case_index, type, description, data, timestamp FROM steps").fetchall()

    conn.close()
    return cases, steps


# ============================================================
# Crash Detection Logic
# ============================================================
def detect_crashes(steps):
    crashes = []

    for step in steps:
        case_num, step_type, desc, data, ts = step

        if desc:
            d = desc.lower()

            if "reset" in d:
                crashes.append((case_num, ts, "connection reset"))

            elif "check failed" in d:
                crashes.append((case_num, ts, "monitor failure"))

            elif "exception" in d:
                crashes.append((case_num, ts, "exception thrown"))

    return crashes


# ============================================================
# Extract Payload from DB
# ============================================================
def extract_payload_from_db(case_num, steps):
    payload = None

    for step in steps:
        cnum, step_type, desc, data, ts = step

        if cnum != case_num:
            continue

        if data not in (None, b""):
            payload = data

    if payload is None:
        return b"", 0

    return payload, len(payload)


# ============================================================
# Extract Payloads from fuzz_log.csv
# ============================================================
def load_payloads_from_log(csv_path):
    payloads = {}
    last_case = None

    try:
        with open(csv_path, "r", errors="ignore") as f:
            for line in f:
                # Detect test case
                m = re.search(r"Test case\s+(\d+)", line)
                if m:
                    last_case = int(m.group(1))
                    continue

                # Detect Python bytes literal:  b'....'
                if "b'" in line:
                    try:
                        txt = line[line.index("b'"):]
                        payload = eval(txt)
                        payloads[last_case] = payload
                    except:
                        pass

        return payloads
    except FileNotFoundError:
        print("[!] fuzz_log.csv not found. Skipping CSV payloads.")
        return {}


# ============================================================
# Ingest Data 
# ============================================================
def ingest_data():
    print("[+] Loading old tables...")
    cases, steps = load_old_tables()

    new_conn = sqlite3.connect(NEW_DB)
    create_new_schema(new_conn)
    cur = new_conn.cursor()

    # Insert fuzz run
    cur.execute(
        "INSERT INTO fuzz_runs (start_time, total_cases, total_crashes) VALUES (?, ?, ?)",
        (datetime.now().isoformat(), len(cases), 0))
    run_id = cur.lastrowid

    # Map case numbers to new IDs
    case_id_map = {}

    print("[+] Inserting test cases...")
    for name, number, ts in cases:
        cur.execute("""INSERT INTO test_cases (run_id, case_number, case_name, timestamp)
                       VALUES (?, ?, ?, ?)""",
                       (run_id, number, name, ts))
        case_id_map[number] = cur.lastrowid

    print("[+] Detecting crashes from steps...")
    crash_events = detect_crashes(steps)

    print("[+] Loading payloads from fuzz_log.csv...")
    payload_map = load_payloads_from_log(CSV_FILE)

    crash_count = 0

    for case_num, ts, reason in crash_events:
        case_id = case_id_map.get(case_num)

        # Insert crash metadata
        cur.execute("""INSERT INTO crashes (case_id, run_id, timestamp, crash_reason)
                       VALUES (?, ?, ?, ?)""",
                       (case_id, run_id, ts, reason))
        crash_id = cur.lastrowid

        # Load from DB if present
        payload, size = extract_payload_from_db(case_num, steps)

        # Otherwise use CSV payload
        if size == 0 and case_num in payload_map:
            payload = payload_map[case_num]
            size = len(payload)

        # Insert payload row
        cur.execute("""INSERT INTO crash_inputs (crash_id, payload, payload_size)
                       VALUES (?, ?, ?)""",
                       (crash_id, payload, size))

        crash_count += 1

    # Update crash count
    cur.execute("UPDATE fuzz_runs SET total_crashes=? WHERE run_id=?", (crash_count, run_id))

    new_conn.commit()
    new_conn.close()

    print(f"[+] Ingestion completed. {crash_count} crashes recorded.")


if __name__ == "__main__":
    ingest_data()
