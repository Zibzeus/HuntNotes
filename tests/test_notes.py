import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

FIX = Path(__file__).parent / "fixtures"


class Workflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.environ["HUNTNOTES_DB"] = str(Path(self.tmp.name) / "notes.sqlite3")
        import app
        app.DB = Path(os.environ["HUNTNOTES_DB"])
        app.initialize()
        self.c = TestClient(app.app, base_url="http://localhost", follow_redirects=False)
        self.addCleanup(self.c.close)
        self.token = re.search('name="csrf" value="([^"]+)"', self.c.get("/").text)[1]

    def post(self, path, *, file=None, **fields):
        return self.c.post(path, data=dict(csrf=self.token, **fields),
                           files={"file": file} if file else None)

    def create(self, name="Archive Workshop"):
        r = self.post("/programs", name=name, policy_url="https://example.invalid/policy")
        self.assertEqual(r.status_code, 303, r.text)
        return r.headers["location"].split("?")[0]

    def records(self, p):
        return self.c.get(p + "/export/json").json()["records"]

    def test_complete_workflow_and_restart(self):
        p = self.create()
        r = self.post(p+"/program", mode="scope", file=("SCOPE_RULES.json",(FIX/"SCOPE_RULES.json").read_bytes()))
        self.assertEqual(r.status_code,303,r.text)
        def save(kind, **kw):
            response = self.post(p+"/records/"+kind, **kw)
            self.assertEqual(response.status_code,303,response.text)
            return next(r for r in reversed(self.records(p)) if r["kind"]==kind)["id"]
        mid = save("model",title="Archive access",assets="Research notes",trust_boundaries="Personal account",
                   entry_points="Archive reader",authentication="Session",authorization="Ownership",abuse_scenarios="Shared archive")
        hyp = save("hypothesis",title="Check archive ownership",question="Is ownership explicit?",status="Open")
        raw = b"\xef\xbb\xbf"+(FIX/"artex-findings.csv").read_bytes()
        eid = save("evidence",source_reference="ARTEX fixture session 7",origin="ARTEX",file=("findings.csv",raw))
        save("hypothesis",id=hyp,title="Check archive ownership",question="Is ownership explicit?",status="Investigating",evidence_id=eid)
        save("journal",title="Ownership review",hypothesis_id=hyp,evidence_id=eid,action="Read archived policy",outcome="Owner documented",next_question="Does the policy cover delegates?")
        journal=self.c.get(p,params={"tab":"journal","q":"delegates"})
        self.assertIn("Ownership review",journal.text)
        self.assertIn("No matching records",self.c.get(p,params={"tab":"journal","q":"unrelated"}).text)
        self.assertNotIn("Check archive ownership",self.c.get(p+"/export/KNOWN_FINDINGS.md").text)
        save("finding",title="Published policy change",status="Historical disclosure",source_reference="Fixture publication 17",
             affected_assets="Archive",category="Policy",duplicate_references="Historical item 4",evidence_id=eid)
        export=self.c.get(p+"/export/json").json()
        self.assertIn("billing",export["program"]["exclusions"])
        ev=next(r for r in export["records"] if r["id"]==eid)
        self.assertEqual(ev["sha256"],hashlib.sha256(raw).hexdigest())
        self.assertEqual(ev["observations"][0]["ID"],"case:7")
        self.assertEqual(len([r for r in export["records"] if r["id"]==hyp]),1)
        self.assertIn("Investigating",export["documents"]["HUNT_BACKLOG.md"])
        self.assertIn("Historical item 4",export["documents"]["KNOWN_FINDINGS.md"])
        with zipfile.ZipFile(io.BytesIO(self.c.get(p+"/export/md").content)) as z:
            self.assertEqual(set(z.namelist()),set(export["documents"]))
            self.assertEqual(len(z.namelist()),7)
            self.assertIn(mid,z.read("ATTACK_SURFACES.md").decode())
            self.assertIn(eid,z.read("RESEARCH_LOG.md").decode())
        for tab in ("overview","model","hypothesis","finding","journal","documents","evidence"):
            self.assertEqual(self.c.get(p,params={"tab":tab}).status_code,200)
        # Fresh interpreter opens the same on-disk database and reads the public export.
        code = "from fastapi.testclient import TestClient;from app import app;import sys;print(TestClient(app,base_url='http://localhost').get(sys.argv[1]).json()['program']['id'])"
        self.assertEqual(subprocess.check_output([sys.executable,"-c",code,p+"/export/json"],text=True).strip(),p.split("/")[-1])

    def test_metadata_and_document_editions(self):
        p=self.post("/programs",mode="import",file=("PROGRAM_METADATA.json",(FIX/"PROGRAM_METADATA.json").read_bytes())).headers["location"].split("?")[0]
        data=self.c.get(p+"/export/json").json()
        self.assertEqual(data["program"]["restrictions"],"Documentation review only.")
        def revision():
            return re.search('name="revision" value="([^"]+)"',self.c.get(p,params={"tab":"documents","doc":"HUNT_BACKLOG.md"}).text)[1]
        url=p+"/documents/HUNT_BACKLOG.md"
        rev=revision()
        self.assertEqual(self.post(url,body="My notes",revision=rev).status_code,303)
        self.assertEqual(self.post(url,body="Stale",revision=rev).status_code,409)
        self.post(p+"/records/hypothesis",title="New idea",status="Open")
        self.assertEqual(self.c.get(p+"/export/HUNT_BACKLOG.md").text,"My notes")
        self.assertEqual(self.post(url,body="My notes",revision=revision(),mode="restore").status_code,303)
        self.assertIn("New idea",self.c.get(p+"/export/HUNT_BACKLOG.md").text)

    def test_untrusted_and_cross_program_inputs(self):
        p=self.create()
        other=self.create("Other")
        url=p+"/records/evidence"
        for name,raw in [("../secret.md",b"x"),("notes.zip",b"PK"),("a.md",b"bad\x00"),("weird.csv",b"wrong,header")]:
            self.assertEqual(self.post(url,source_reference="local",origin="ARTEX",file=(name,raw)).status_code,400)
        self.assertEqual(self.post(url,origin="ARTEX",source_reference="local",file=("note.md",b"<script>alert(1)</script>")).status_code,303)
        eid=self.records(p)[0]["id"]
        self.assertIn("&lt;script&gt;",self.c.get(p+"/evidence/"+eid).text)
        self.assertEqual(self.c.get(other+"/evidence/"+eid).status_code,404)
        self.assertEqual(self.post(other+"/records/hypothesis",title="Cross link",status="Open",evidence_id=eid).status_code,400)
        self.assertEqual(self.post(p+"/records/finding",title="Unattributed",status="Researcher verified").status_code,400)
        self.assertEqual(self.c.post("/programs",data={"name":"forged"}).status_code,403)
        self.assertEqual(self.c.get("/",headers={"Host":"untrusted.invalid"}).status_code,400)
        self.assertEqual(self.post(url,source_reference="local",file=("big.md",b"x"*1048576)).status_code,413)
        self.assertEqual(self.post("/programs",mode="import",file=("broken.json",b"[]")).status_code,400)


if __name__=="__main__":
    unittest.main()
