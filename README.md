# VChat Fuzzing Analysis Database  
*A Crash Analytics System for Boofuzz Fuzz Runs (TRUN, GTER, and Additional Commands)*

This project implements a complete **fuzzing analytics database system** for crashes discovered while fuzzing the vulnerable VChat server using Boofuzz.  
It transforms raw fuzzing output into a clean, normalized SQLite database that supports querying, analysis, visualization, and multi-run comparison.

This project was developed as part of a database course, but it also serves as a real-world example of cybersecurity data engineering, fuzzing instrumentation, and structured crash analysis.

---

# Project Overview

Boofuzz generates valuable but **unstructured** output when fuzzing a program:

- Thousands of test cases  
- Crash events  
- Packet payloads (text and binary)  
- Event logs  
- Internal “steps” describing send/receive operations  

This project ingests those raw artifacts and converts them into a **normalized relational schema** suitable for:

- Querying  
- Analysis  
- Visualization  
- Comparing fuzz runs  
- Understanding which inputs cause program instability  

The ingestion pipeline supports **multiple fuzz runs**, such as:

- `TRUN`
- `GTER`
- (Any other VChat command you fuzz)

Each run is tracked independently in the final `vchat_fuzz_analysis.db`.

---

# Database Schema (Simplified, 3NF)

This project uses a clean four-table schema:

```
fuzz_runs (1) ───────< test_cases (1) ───────< crashes (1) ───────< crash_inputs
```

---

### **Table: fuzz_runs**  
Represents one fuzzing session.

| Column | Description |
|--------|-------------|
| run_id (PK) | Unique fuzz run ID |
| start_time | Timestamp when ingestion occurred |
| end_time | Optional |
| total_cases | Number of test cases in this run |
| total_crashes | Number of crashes detected |

---

### **Table: test_cases**

| Column | Description |
|--------|-------------|
| case_id (PK) | Unique ID for test case |
| run_id (FK) | References fuzz_runs |
| case_number | Sequential test case number |
| case_name | Mutation name (e.g., `TRUN:[TRUN-STRING:35]`) |
| timestamp | Timestamp extracted from fuzz data |

---

### **Table: crashes**

| Column | Description |
|--------|-------------|
| crash_id (PK) | Crash event ID |
| case_id (FK) | The test case that caused the crash |
| run_id (FK) | The fuzz run containing this crash |
| timestamp | Crash timestamp |
| crash_reason | Detected reason (e.g., connection reset, monitor failure) |

---

### **Table: crash_inputs**

| Column | Description |
|--------|-------------|
| input_id (PK) | Unique payload ID |
| crash_id (FK) | References crashes |
| payload (BLOB) | Crash-causing payload (binary or text) |
| payload_size | Size in bytes |

---

# ER Diagram

```
┌──────────────┐        ┌────────────────┐        ┌───────────────┐        ┌─────────────────┐
│  fuzz_runs   │ 1    ∞ │  test_cases    │ 1    ∞ │    crashes    │ 1    1 │  crash_inputs   │
├──────────────┤        ├────────────────┤        ├───────────────┤        ├─────────────────┤
│ run_id (PK)  │◄────── │ case_id (PK)   │◄────── │ crash_id (PK) │◄────── │ input_id (PK)   │
│ start_time   │        │ run_id (FK)    │        │ case_id (FK)  │        │ payload (BLOB)  │
│ total_cases  │        │ case_number    │        │ run_id (FK)   │        │ payload_size    │
│ total_crashes│        │ case_name      │        │ timestamp     │        └─────────────────┘
└──────────────┘        └────────────────┘        │ crash_reason  │
                                                  └───────────────┘
```

---

# Ingestion Pipeline

The ingestion script (`ingest2.py`) performs:

### ✔ Loading Boofuzz `.db` results (`cases` + `steps`)  
### ✔ Detecting crashes based on descriptions like:  
- "connection reset"  
- "check failed"  
- "exception thrown"  

### ✔ Extracting payloads from:  
- `steps.data` (raw BLOBs)  
- Fuzz logs (`fuzz_log.csv`) as a fallback  

### ✔ Normalizing the data into the simplified schema  
### ✔ Adding a new fuzz run instead of overwriting  

This allows you to ingest:

- TRUN fuzz run  
- GTER fuzz run  
- Any future fuzz runs  

All into the same analysis database.

---

# Running the Ingestion

```
python ingest.py
```

The script will:

1. Read the original Boofuzz database  
2. Read fuzz logs if available  
3. Detect crash events  
4. Extract payloads  
5. Insert everything into `vchat_fuzz_analysis.db`  

---

# Example SQL Queries

Below are some examples

### **Find all test cases that crashed**
```sql
SELECT 
    tc.case_id,
    tc.case_number,
    tc.case_name,
    tc.run_id,
    c.crash_reason,
    c.timestamp AS crash_time
FROM crashes c
JOIN test_cases tc ON tc.case_id = c.case_id
ORDER BY tc.case_number;
```

### **Test cases that never crashed**
```sql
SELECT 
    fr.run_id,
    fr.start_time,
    fr.total_cases,
    fr.total_crashes
FROM fuzz_runs fr
WHERE fr.total_crashes = 0
ORDER BY fr.run_id;

```

### **Show the payloads for all crashes**
```sql
SELECT 
    c.crash_id,
    tc.case_number,
    tc.case_name,
    ci.payload_size,
    ci.payload
FROM crash_inputs ci
JOIN crashes c ON c.crash_id = ci.crash_id
JOIN test_cases tc ON tc.case_id = c.case_id
ORDER BY ci.payload_size DESC;
```
### **Show crash payloads for a specific command (e.g., TRUN, GTER)**
```sql
SELECT 
    tc.case_name,
    c.crash_reason,
    ci.payload_size,
    ci.payload
FROM crash_inputs ci
JOIN crashes c ON c.crash_id = ci.crash_id
JOIN test_cases tc ON tc.case_id = c.case_id
WHERE tc.case_name LIKE 'TRUN%'
ORDER BY ci.payload_size DESC;

```
---

# License

MIT License

