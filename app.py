import csv
import hashlib
import io
import json
import os
import secrets
import sqlite3
import zipfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from model import DOCS, FIELDS, PROGRAM, STATUS, evidence, generated, now, radar, uid

BASE = Path(__file__).resolve().parent
DATA_HOME = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
DB = Path(os.environ.get("HUNTNOTES_DB", DATA_HOME / "huntnotes-lite" / "notes.sqlite3"))
LIMIT = 1024 * 1024
TOKEN = secrets.token_urlsafe(32)
VIEWS = ("overview", "model", "hypothesis", "evidence", "finding", "journal", "documents")
NAMES = dict(overview="Overview", model="Threat models", hypothesis="Hypotheses", evidence="Evidence",
             finding="Known findings", journal="Journal", documents="Documents")
app = FastAPI(title="HuntNotes Lite", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals.update(csrf=TOKEN, fields=FIELDS, statuses=STATUS, names=NAMES, program_fields=PROGRAM)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@contextmanager
def db():
    con = sqlite3.connect(DB, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()


def initialize():
    DB.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS programs(id TEXT PRIMARY KEY, data TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, pid TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, updated TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS records_program ON records(pid,kind);
        CREATE TABLE IF NOT EXISTS edits(pid TEXT, name TEXT, body TEXT NOT NULL, PRIMARY KEY(pid,name));
        """)


initialize()


@app.middleware("http")
async def boundaries(req, call_next):
    if req.method == "POST":
        size = req.headers.get("content-length", "")
        if not size.isdecimal() or len(size) > 10 or int(size) > LIMIT or "transfer-encoding" in req.headers:
            return PlainTextResponse("Import or form exceeds the 1 MiB request limit or lacks a fixed length.", 413)
    response = await call_next(req)
    response.headers.update({"Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                             "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
    return response


@app.exception_handler(HTTPException)
async def invalid(req, error):
    return templates.TemplateResponse(req, "error.html", {"message": error.detail}, status_code=error.status_code)


def require(condition, message, status=400):
    if not condition:
        raise HTTPException(status, message)


async def form(req):
    values = await req.form(max_files=1, max_fields=24, max_part_size=LIMIT)
    require(values.get("csrf") == TOKEN, "Form expired. Reopen the page and try again.", 403)
    return values


def inputs(values, keys):
    result = {}
    for k in keys:
        value = values.get(k, "")
        require(isinstance(value, str) and len(value) <= 65536, "Invalid or oversized field: " + k)
        result[k] = value.strip()
    return result


def program(con, pid):
    row = con.execute("SELECT * FROM programs WHERE id=?", (pid,)).fetchone()
    require(row, "Program not found.", 404)
    return dict(json.loads(row["data"]), id=pid, updated=row["updated"])


def check_program(p):
    require(p.get("name", "").strip() and len(p["name"]) <= 200, "Enter a program name of up to 200 characters.")
    url = p.get("policy_url", "")
    try:
        valid = not url or (urlsplit(url).scheme in ("https", "http") and urlsplit(url).hostname)
    except ValueError:
        valid = False
    require(valid, "Enter an HTTP or HTTPS official policy URL.")


def unpack(r):
    return dict(json.loads(r["data"]), id=r["id"], kind=r["kind"], updated=r["updated"])


def rows(con, pid, light=False):
    data = "json_remove(data,'$.content','$.observations')" if light else "data"
    return [unpack(r) for r in con.execute(f"SELECT id,kind,updated,{data} AS data FROM records WHERE pid=? ORDER BY rowid", (pid,))]


def redirect(pid, tab="overview", **options):
    return RedirectResponse("/p/" + pid + "?" + urlencode({"tab": tab, **options}), 303)


def docset(con, p, items):
    auto = generated(p, items)
    saved = dict(con.execute("SELECT name,body FROM edits WHERE pid=?", (p["id"],)))
    return auto, saved


@app.get("/")
def home(request: Request):
    with db() as con:
        programs = [dict(r) for r in con.execute("SELECT id,updated,json_extract(data,'$.name') AS name,json_extract(data,'$.policy_url') AS policy_url FROM programs ORDER BY updated DESC")]
    return templates.TemplateResponse(request, "home.html", {"programs": programs})


async def uploaded(f):
    file = f.get("file")
    require(hasattr(file, "read") and file.filename, "Choose a file.")
    try:
        raw = await file.read(LIMIT)
    finally:
        await file.close()
    require(raw, "This file is empty.")
    return file.filename, raw


def parse(parser, *args):
    try:
        return parser(*args)
    except (ValueError, RecursionError, csv.Error) as exc:
        raise HTTPException(400, "Unsupported import. " + str(exc)[:180]) from exc


@app.post("/programs")
async def create(req: Request):
    f = await form(req)
    p = inputs(f, PROGRAM)
    if f.get("mode") == "import":
        name, raw = await uploaded(f)
        imported = parse(radar, raw)
        p.update(imported)
    check_program(p)
    pid = uid()
    with db() as con:
        con.execute("INSERT INTO programs VALUES(?,?,?)", (pid, json.dumps(p), now()))
        if f.get("mode") == "import":
            insert(con, pid, "evidence", parse(evidence, name, raw, "BountyRadar program metadata"))
    return redirect(pid)


@app.get("/p/{pid}")
def workspace(request: Request, pid: str, tab: str = "overview", edit: str = "", q: str = "", doc: str = DOCS[0]):
    require(tab in VIEWS and doc in DOCS, "Unknown workspace section.", 404)
    with db() as con:
        p = program(con, pid)
        items = rows(con, pid, True)
        editing = next((r for r in items if r["id"] == edit and r["kind"] == tab), {})
        require(not edit or editing, "Record not found in this program.", 404)
        entries = [r for r in reversed(items) if r["kind"] == tab and
                   (not q or q.casefold() in json.dumps(r, ensure_ascii=False).casefold())]
        auto, saved = docset(con, p, items) if tab == "documents" else ({}, {})
        body = saved.get(doc, auto.get(doc, ""))
    return templates.TemplateResponse(request, "workspace.html", dict(p=p, tab=tab, items=items, entries=entries,
        editing=editing, q=q, docs=DOCS, doc=doc, body=body, saved=saved, auto=auto,
        revision=hashlib.sha256(body.encode()).hexdigest()))


@app.post("/p/{pid}/program")
async def update_program(req: Request, pid: str):
    f = await form(req)
    with db() as con:
        p = program(con, pid)
        p.pop("id")
        p.pop("updated")
        if f.get("mode") == "scope":
            name, raw = await uploaded(f)
            scope = parse(radar, raw, True)
            origin = json.loads(scope["provenance"])
            require(not p["policy_url"] or p["policy_url"] == origin["url"], "Scope export belongs to a different policy URL.")
            if not p["policy_url"]:
                p["policy_url"] = origin["url"]
            scope["provenance"] = "\n".join(filter(None, (p["provenance"], scope["provenance"])))
            p.update(scope)
            insert(con, pid, "evidence", parse(evidence, name, raw, "BountyRadar scope snapshot"))
        else:
            p = inputs(f, PROGRAM)
        check_program(p)
        con.execute("UPDATE programs SET data=?,updated=? WHERE id=?", (json.dumps(p), now(), pid))
    return redirect(pid)


def insert(con, pid, kind, data):
    con.execute("INSERT INTO records VALUES(?,?,?,?,?)", (uid(), pid, kind, json.dumps(data, ensure_ascii=False), now()))


@app.post("/p/{pid}/records/{kind}")
async def save_record(req: Request, pid: str, kind: str):
    f = await form(req)
    require(kind in (*FIELDS, "evidence"), "Unknown record type.", 404)
    with db() as con:
        program(con, pid)
        if kind == "evidence":
            name, raw = await uploaded(f)
            source = inputs(f, ("source_reference",))["source_reference"]
            require(source, "Enter a source reference.")
            insert(con, pid, kind, parse(evidence, name, raw, source, f.get("origin") == "ARTEX"))
        else:
            data = inputs(f, FIELDS[kind])
            require(data["title"], "Enter a title.")
            if kind in STATUS:
                require(data["status"] in STATUS[kind], "Choose a listed research status.")
            if kind == "finding":
                require(data["source_reference"], "A sourced finding requires a reference.")
            for k, target in (("evidence_id","evidence"), ("hypothesis_id","hypothesis")):
                if data.get(k):
                    require(con.execute("SELECT 1 FROM records WHERE pid=? AND id=? AND kind=?", (pid,data[k],target)).fetchone(),
                            "Linked record not found in this program.")
            if f.get("id"):
                result = con.execute("UPDATE records SET data=?,updated=? WHERE pid=? AND id=? AND kind=?",
                                     (json.dumps(data), now(), pid, f["id"], kind))
                require(result.rowcount, "Record not found.", 404)
            else:
                insert(con, pid, kind, data)
    return redirect(pid, kind)


@app.get("/p/{pid}/evidence/{eid}")
def inspect(request: Request, pid: str, eid: str):
    with db() as con:
        p = program(con, pid)
        r = con.execute("SELECT * FROM records WHERE pid=? AND id=? AND kind='evidence'", (pid,eid)).fetchone()
        require(r, "Evidence not found.", 404)
        return templates.TemplateResponse(request, "evidence.html", dict(p=p, e=unpack(r)))


@app.post("/p/{pid}/documents/{name}")
async def save_document(req: Request, pid: str, name: str):
    require(name in DOCS, "Unknown document.", 404)
    f = await form(req)
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        p = program(con, pid)
        auto, saved = docset(con, p, rows(con, pid, True))
        current = saved.get(name, auto[name])
        require(f.get("revision") == hashlib.sha256(current.encode()).hexdigest(), "Document changed. Reload before editing.", 409)
        body = f.get("body")
        require(isinstance(body, str), "Missing document body.")
        body = body.replace("\r\n", "\n")
        if body != current:
            con.execute("INSERT OR REPLACE INTO edits VALUES(?,?,?)", (pid,name,body))
        if f.get("mode") == "restore":
            con.execute("DELETE FROM edits WHERE pid=? AND name=?", (pid,name))
    return redirect(pid, "documents", doc=name)


@app.get("/p/{pid}/export/{fmt}")
def export(pid: str, fmt: str):
    require(fmt in ("md", "json", *DOCS), "Unknown format.", 404)
    with db() as con:
        con.execute("BEGIN")
        p = program(con, pid)
        auto, saved = docset(con, p, rows(con, pid, True))
        docs = {**auto, **saved}
        if fmt == "json":
            # Stream evidence one record at a time from one coherent read snapshot.
            import tempfile
            out = tempfile.TemporaryFile()
            try:
                prefix = dict(schema_version=1, program=p, documents=docs, edited_documents=list(saved))
                out.write((json.dumps(prefix, ensure_ascii=False)[:-1] + ', "records":[').encode())
                for i,r in enumerate(con.execute("SELECT * FROM records WHERE pid=? ORDER BY rowid", (pid,))):
                    out.write((("," if i else "") + json.dumps(unpack(r), ensure_ascii=False)).encode())
                out.write(b"]}")
                out.seek(0)
            except BaseException:
                out.close()
                raise
            def chunks():
                with out:
                    while chunk := out.read(65536):
                        yield chunk
            return StreamingResponse(chunks(), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{pid}.json"'})
        if fmt in DOCS:
            return Response(docs[fmt], media_type="text/markdown", headers={"Content-Disposition":f'attachment; filename="{fmt}"'})
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
            for name, body in docs.items():
                z.writestr(name, body)
        return Response(buffer.getvalue(), media_type="application/zip", headers={"Content-Disposition":f'attachment; filename="{pid}-workspace.zip"'})
