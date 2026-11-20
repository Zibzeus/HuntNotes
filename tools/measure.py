"""Measure a disposable loopback server on Windows or Linux. Uses test dependency httpx."""
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def resident(pid):
    if os.name == "nt":
        values = subprocess.check_output(["powershell.exe", "-NoProfile", "-Command",
            f"$p=Get-Process -Id {pid}; Write-Output $p.WorkingSet64,$p.PeakWorkingSet64,$p.TotalProcessorTime.Ticks"], text=True).split()
        return int(values[0]), int(values[1]), int(values[2])/10_000_000
    status = Path(f"/proc/{pid}/status").read_text()
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (*(int(re.search(k+r":\s+(\d+)", status)[1])*1024 for k in ("VmRSS","VmHWM")),
            (int(stat[11])+int(stat[12])) / os.sysconf("SC_CLK_TCK"))


def measure():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp)
        db = path / "sample.sqlite3"
        log = path / "server.log"
        with log.open("wb") as stream:
            proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "0"],
                cwd=ROOT, env={**os.environ, "HUNTNOTES_DB":str(db)}, stdout=stream, stderr=stream)
        try:
            for _ in range(150):
                output=log.read_text(errors="replace")
                match=re.search(r"Uvicorn running on (http://127\.0\.0\.1:\d+)",output)
                if match:
                    break
                if proc.poll() is not None:
                    raise RuntimeError(output)
                time.sleep(.1)
            else:
                raise TimeoutError("Loopback server did not start")
            with httpx.Client(base_url=match[1],trust_env=False) as c:
                page=c.get("/").raise_for_status()
                token=re.search('name="csrf" value="([^"]+)"',page.text)[1]
                idle,_,cpu_start=resident(proc.pid)
                t=time.perf_counter()
                fixture=(ROOT/"tests/fixtures/PROGRAM_METADATA.json").read_bytes()
                r=c.post("/programs",data={"csrf":token,"mode":"import"},files={"file":("PROGRAM_METADATA.json",fixture)})
                assert r.status_code==303,r.text
                program=r.headers["location"].split("?")[0]
                for i in range(10):
                    r=c.post(program+"/records/evidence",data={"csrf":token,"source_reference":f"local-{i}"},
                        files={"file":(f"report-{i}.md",b"sample evidence\n"*4096)})
                    assert r.status_code==303,r.text
                exported=c.get(program+"/export/json").raise_for_status()
                assert len(exported.json()["records"])==11
                md=c.get(program+"/export/md").raise_for_status()
                elapsed=time.perf_counter()-t
                final,peak,cpu_end=resident(proc.pid)
                return dict(os=platform.system(),python=platform.python_version(),idle_rss_mib=round(idle/2**20,1),
                    after_rss_mib=round(final/2**20,1),peak_rss_mib=round(peak/2**20,1),
                    db_bytes=db.stat().st_size,json_bytes=len(exported.content),markdown_zip_bytes=len(md.content),
                    workflow_seconds=round(elapsed,3),server_cpu_seconds=round(cpu_end-cpu_start,3))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__=="__main__":
    print(json.dumps(measure(),indent=2))
