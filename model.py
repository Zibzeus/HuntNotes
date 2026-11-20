"""Portable records, BountyRadar scope and offline ARTEX evidence."""
import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from uuid import uuid4


def uid():
    return str(uuid4())


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


PROGRAM = ("name", "policy_url", "scope", "exclusions", "restrictions", "notes", "provenance")
FIELDS = {
    "model": ("title", "assets", "trust_boundaries", "entry_points", "authentication", "authorization", "abuse_scenarios"),
    "hypothesis": ("title", "question", "asset", "status", "evidence_id"),
    "finding": ("title", "affected_assets", "category", "source_reference", "duplicate_references", "status", "evidence_id"),
    "journal": ("title", "hypothesis_id", "action", "evidence_id", "outcome", "next_question"),
}
STATUS = {"hypothesis": ("Open", "Investigating", "Supported", "Rejected", "Deferred"),
          "finding": ("Historical disclosure", "Researcher verified")}
DOCS = ("PROGRAM_SCOPE.md", "PROGRAM_POLICY.md", "THREAT_MODEL.md", "ATTACK_SURFACES.md",
        "KNOWN_FINDINGS.md", "HUNT_BACKLOG.md", "RESEARCH_LOG.md")
CSV_HEADER = "ID 名称 类别 严重等级 状态 所属任务 发现时间 概述 流量证据数量 流量证据ID".split()


def printable(value):
    if value is None:
        return ""
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def radar(raw, scope_only=False):
    obj = json.loads(raw)
    key = "rules" if scope_only else "scope"
    if not isinstance(obj, dict) or obj.get("schema_version") != "1.0" or not obj.get("snapshot_id"):
        raise ValueError("Expected a BountyRadar v1 export with a snapshot ID.")
    if not isinstance(obj.get("url"), str) or not obj["url"]:
        raise ValueError("The snapshot is missing its official policy URL.")
    if scope_only and key not in obj or not scope_only and not isinstance(obj.get("name"), str):
        raise ValueError("Choose the matching BountyRadar export file.")
    rules = obj.get(key)
    if rules is not None and not isinstance(rules, list):
        raise ValueError("Invalid scope rule list.")
    parts = {"include": [], "exclude": [], "unknown": []}
    for rule in rules or []:
        if not isinstance(rule, dict) or rule.get("effect") not in parts or not isinstance(rule.get("raw"), str):
            raise ValueError("Invalid BountyRadar scope rule.")
        parts[rule["effect"]].append(rule["raw"])
    provenance = {k: obj.get(k) for k in ("id", "snapshot_id", "url", "provenance", "acquired_at", "verification", "ambiguities")}
    if parts["unknown"]:
        provenance["unresolved_rules"] = parts["unknown"]
    result = dict(scope="\n".join(parts["include"]) or ("Unknown" if rules is None else "No included rules listed."),
                  exclusions="\n".join(parts["exclude"]), provenance=printable(provenance))
    if not scope_only:
        result.update(name=obj["name"], policy_url=printable(obj.get("url")),
                      restrictions=printable(obj.get("testing_restrictions")), notes=printable(obj.get("policy")))
        if obj.get("out_of_scope"):
            result["exclusions"] += "\n" + printable(obj["out_of_scope"])
    return result


def evidence(name, raw, source, artex=False):
    ext = name.rsplit(".", 1)[-1].lower()
    allowed = {"md", "csv"} if artex else {"md", "txt", "json", "csv", "log", "http"}
    if ext not in allowed or any(c in name for c in "/\\:\x00") or not raw or len(name) > 240:
        raise ValueError("Choose a supported UTF-8 file with a plain filename. Archives are not accepted.")
    body = raw.decode("utf-8-sig")
    if "\x00" in body:
        raise ValueError("Binary evidence is not supported.")
    row = dict(title=name, source_reference=source, origin="ARTEX" if artex else "Researcher",
               sha256=hashlib.sha256(raw).hexdigest(), content=body, utf8_bom=raw.startswith(b"\xef\xbb\xbf"))
    if artex and ext == "csv":
        reader = csv.reader(io.StringIO(body, newline=""), strict=True)
        if next(reader, None) != CSV_HEADER:
            raise ValueError("Unrecognized ARTEX findings CSV header. Import the Markdown export instead.")
        observations = []
        for fields in reader:
            if len(fields) != len(CSV_HEADER) or not fields[0] or len(observations) >= 2000:
                raise ValueError("Invalid ARTEX row or more than 2,000 observations.")
            observations.append(dict(zip(CSV_HEADER, fields)))
        row["observations"] = observations
    return row


def section(title, fields):
    return "## " + title + "\n\n" + "\n\n".join(
        "**" + k.replace("_", " ").title() + "**\n\n" + printable(v)
        for k, v in fields.items() if v not in ("", None)) + "\n"


def generated(program, rows):
    docs = {n: "# " + n[:-3].replace("_", " ").title() + " — " + program["name"] + "\n\n"
            + "Program ID: " + program["id"] + "\n\n" for n in DOCS}
    for n, keys in [(DOCS[0], ("scope", "exclusions", "provenance")),
                    (DOCS[1], ("policy_url", "restrictions", "notes", "provenance"))]:
        docs[n] += section("Program record", {k: program.get(k) for k in keys})
    for row in rows:
        kind = row["kind"]
        keys = ("id", "updated", *FIELDS.get(kind, ("source_reference", "sha256")))
        data = {k: row.get(k) for k in keys if k != "title"}
        dest = {"model": 2, "finding": 4, "hypothesis": 5, "journal": 6, "evidence": 6}[kind]
        docs[DOCS[dest]] += "\n" + section(row["title"], data)
        if kind == "model":
            docs[DOCS[3]] += "\n" + section(row["title"], {k: row.get(k) for k in ("id", "assets", "trust_boundaries", "entry_points")})
    return docs
