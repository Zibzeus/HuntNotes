# HuntNotes Lite

A single-user research notebook that runs on localhost. One Python process serves the interface and one SQLite database holds programs, scope snapshots, structured research records, evidence and document edits. BountyRadar and ARTEX exchange files with the notebook and run independently.

## Install and start

Use Python 3.11+ with the standard SQLite module, a virtual environment and a current browser. Python 3.14.5 was tested. Run these commands in the directory containing this README.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8765
```

On Windows PowerShell use these commands instead:

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8765
```

Open [HuntNotes Lite](http://127.0.0.1:8765). Stop with Ctrl+C. Use one Uvicorn worker. The app trusts the local OS account and has no application login. On a private Linux server, run it under your own account and access its loopback port through an SSH tunnel. The app has no background scheduler, client JavaScript, CDN, model dependency or external data requests.

## First research session

1. Create a program and enter the official policy URL, or import a BountyRadar v1 `PROGRAM_METADATA.json` file. If starting from its workspace ZIP, select the individual JSON file from your existing export. HuntNotes does not extract archives.
2. In **Overview → Import scope snapshot**, select `SCOPE_RULES.json`. The original JSON is retained as evidence. An imported scope updates included assets and exclusions and keeps the snapshot provenance. Unknown rules stay unresolved. You can also edit every program field manually.
3. Under **Threat models**, record assets, entry points, boundaries, authentication, authorization and potential abuse scenarios. Under **Hypotheses**, enter a question and current status.
4. Import a UTF-8 evidence file, identify its origin and provide a session ID, file reference or publication reference. Return to a hypothesis, select its title, link the evidence and update its status. Add a journal entry linking the hypothesis, action, evidence, outcome and next question. Each research section supports text search over its record metadata; journal search includes actions, outcomes and next questions.
5. Record historical disclosures or researcher-verified findings explicitly in **Known findings**. They require a source reference and can link affected assets, category, evidence and duplicates. Changing a hypothesis status or importing an agent observation never creates a verified finding.
6. In **Documents**, open any of the seven workspace files and download its Markdown. A generated document follows structured records automatically. Editing and saving its full text creates a manual edition. Later changes preserve that edition. **Compare generated draft** shows the current alternative; only the explicit replacement button re-enables automatic updates. Stale document saves are rejected.
7. **Overview → Workspace exports** downloads all seven documents in a ZIP or exports JSON. JSON schema version 1 contains the program, records, effective documents and names of manual editions. UUIDs remain stable on edits. Links use those IDs. Individual evidence records include source, filename, original text, SHA-256 and a UTF-8 BOM flag for byte-exact reconstruction. Markdown files contain references; the complete evidence text is in JSON.

## Supported ARTEX imports

Import a single or consolidated Markdown finding report as verbatim evidence. Findings CSV additionally exposes individual observation IDs, titles and summaries, retaining every exported column. CSV supports the inspected ten-column Chinese findings header with optional UTF-8 BOM. Other versions or translated headers are rejected with a message; use their Markdown export. No ARTEX service or credentials are needed. Compatibility was checked against exporter source and representative fixtures. No private ARTEX session data was supplied.

Format references: [ARTEX v0.3.15 report package](https://pkg.go.dev/github.com/Autumn-27/artex@v0.3.15/report) and [reviewed fork's Markdown and CSV exporter](https://github.com/RuoJi6/ARTEX/blob/main/report/findings.go). BountyRadar fixtures in `tests/fixtures` were produced with the sibling project's v1 exporter using fictional program data. The server has no runtime dependency on that project.

## Local storage and security

Linux defaults to `$XDG_DATA_HOME/huntnotes-lite/notes.sqlite3`, or `~/.local/share/huntnotes-lite/notes.sqlite3`. Windows uses `%LOCALAPPDATA%\huntnotes-lite\notes.sqlite3`. Set `HUNTNOTES_DB` to a private database path to override. The source directory can move independently. For a full backup, stop the server and copy the database. To restore, stop the server, select the backup copy using `HUNTNOTES_DB`, then start normally. JSON supports portable consumption; restoration of the entire notebook uses the SQLite backup.

Requests are capped at 1 MiB including form overhead. Imports are text-only. Filenames never become storage paths, archives are rejected, and uploaded text is displayed escaped. Each mutation requires a form token. The server restricts accepted hosts and uses a content security policy. Evidence lookups and links are program-scoped. The single OS user can access all programs via the directory. Database backups and full JSON exports contain the researcher's raw material, including any secrets present in source files. Use private disk permissions; exported Markdown should be opened in a viewer that treats embedded HTML and remote links as untrusted.

## Verification and resource usage

With the environment activated:

```sh
python -m pip install httpx==0.28.1
python -m unittest discover -s tests -v
python tools/measure.py
```

Three integration tests exercise the complete workflow, reopening the database in a fresh interpreter, both BountyRadar imports, ARTEX imports, edit preservation, exports, search, invalid input, request limits and cross-program isolation. A separate Edge run exercised the forms from program creation to Markdown download and checked that the document view fit at 390 and 1,280 CSS pixels.

The measurement script starts a disposable Uvicorn server on an ephemeral loopback port, imports a program snapshot and ten 64 KiB evidence files, downloads both exports, then stops and removes the test database. One Windows x86-64 run with Python 3.14.5 produced:

| Measurement | Observed |
|---|---:|
| Server working set after first page | 58.3 MiB |
| Peak server working set | 61.2 MiB |
| SQLite file after fixture imports | 737,280 bytes |
| JSON export / Markdown ZIP | 705,499 / 2,368 bytes |
| Import and export wall time / server CPU time | 0.116 s / 0.094 s |

The intended starting host is **1–2 vCPU, 2 GB RAM and 10 GB initial disk**, without a GPU. The measurements cover the app process and fixture database, excluding the OS, Python environment, browser and backups. They are evidence for a small notebook, not a constrained-Linux benchmark. Re-run the script on the chosen host. Leave free disk for exports, which can temporarily consume space comparable to the program's records. Directory and generated-document queries scale with program metadata; the app is intended for a personal notebook and small evidence files.
