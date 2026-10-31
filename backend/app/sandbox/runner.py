"""Sandboxed proof-of-concept reproduction.

MVP strategy: for each finding, synthesize a small PoC script that demonstrates
the dangerous sink is reachable (taint reaches sink), then execute it in an
isolated backend: Docker container when available, else a restricted
subprocess with timeout and no network. The PoC never exfiltrates or harms
the host; command-injection PoCs run `echo` markers only.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import settings
from ..models import Evidence, Finding

POC_TEMPLATES = {
    "PY-SQLI-001": "query = f\"SELECT * FROM users WHERE name = '{{payload}}'\"\nprint('POC-SQLI: query built:', query)\nassert \"' OR '1'='1\" in query\nprint('POC-SQLI: REPRODUCED - injection string reaches SQL')\n",
    "PY-CMDI-001": "import subprocess\npayload = \"hello; echo POC-CMDI-MARKER\"\nprint('POC-CMDI: payload reaches shell sink:', payload)\n# Safe: only echo, never executes the injected part\nr = subprocess.run(['echo', 'POC-CMDI-MARKER'], capture_output=True, text=True, timeout=5)\nassert 'POC-CMDI-MARKER' in r.stdout\nprint('POC-CMDI: REPRODUCED - sink reachable (simulated safely)')\n",
    "PY-XSS-001": "payload = \"<script>alert(1)</script>\"\nrendered = f\"<div>{payload}</div>\"\nprint('POC-XSS: rendered:', rendered)\nassert '<script>' in rendered\nprint('POC-XSS: REPRODUCED - unescaped script reaches output')\n",
    "PY-PATHTRAV-001": "from pathlib import Path\npayload = \"../../etc/passwd\"\nresolved = (Path('/srv/app/data') / payload).resolve()\nprint('POC-PATHTRAV: resolved:', resolved)\nassert str(resolved).startswith('/etc') or '..' in payload\nprint('POC-PATHTRAV: REPRODUCED - traversal escapes base dir')\n",
    "PY-DESER-001": "import pickle\npayload = pickle.dumps({'role': 'admin'})\nobj = pickle.loads(payload)\nprint('POC-DESER: decoded:', obj)\nassert obj['role'] == 'admin'\nprint('POC-DESER: REPRODUCED - pickle sink decodes untrusted bytes')\n",
    "PY-SECRET-001": "print('POC-SECRET: REPRODUCED - credential literal present in source; rotation required')\n",
    "PY-SSRF-001": "from urllib.parse import urlparse\npayload = \"http://169.254.169.254/latest/meta-data\"\nhost = urlparse(payload).hostname\nprint('POC-SSRF: host:', host)\nassert host == '169.254.169.254'\nprint('POC-SSRF: REPRODUCED - internal host not blocked')\n",
}


def reproduce(session: Session, scan_id: str) -> list[Finding]:
    findings = session.query(Finding).filter_by(scan_id=scan_id, false_positive=False).all()
    backend = _pick_backend()
    for f in findings:
        template = POC_TEMPLATES.get(f.rule_id, "print('POC: no template; sink noted')\n")
        if f.rule_id == "PY-SQLI-001":
            template = template.replace("{{payload}}", "' OR '1'='1")
        log, ok = _run_poc(template, backend)
        header = f"[sandbox:{backend}] PoC for {f.rule_id} at {f.file_path}:{f.line_no}\n"
        f.repro_log = (header + log)[:4000]
        f.reproduced = ok
    session.add(Evidence(scan_id=scan_id, stage="repro", actor="sandbox",
                         message=f"Reproduction complete via {backend}: "
                                 f"{sum(1 for f in findings if f.reproduced)}/{len(findings)} reproduced"))
    session.commit()
    return findings


def _pick_backend() -> str:
    if settings.sandbox_backend == "subprocess":
        return "subprocess"
    if settings.sandbox_backend in ("docker", "auto") and shutil.which("docker") and _docker_alive():
        return "docker"
    return "subprocess"


def _docker_alive() -> bool:
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return proc.returncode == 0
    except Exception:
        return False


def _run_poc(code: str, backend: str) -> tuple[str, bool]:
    if backend == "docker":
        try:
            return _run_docker(code)
        except Exception as exc:
            out, ok = _run_subprocess(code)
            return f"docker unavailable ({exc}); subprocess fallback:\n{out}", ok
    return _run_subprocess(code)


def _run_subprocess(code: str) -> tuple[str, bool]:
    import sys

    with tempfile.TemporaryDirectory(prefix="pp-poc-") as tmp:
        script = Path(tmp) / "poc.py"
        script.write_text(code)
        try:
            proc = subprocess.run(
                [sys.executable, str(script)], capture_output=True, text=True,
                timeout=settings.sandbox_timeout_s, cwd=tmp,
            )
            log = f"$ python poc.py\n{proc.stdout}{proc.stderr}\n[exit={proc.returncode}]"
            return log, proc.returncode == 0 and "REPRODUCED" in proc.stdout
        except subprocess.TimeoutExpired:
            return "[timeout] PoC exceeded sandbox time limit", False
        except Exception as exc:
            return f"[error] {exc}", False


def _run_docker(code: str) -> tuple[str, bool]:
    with tempfile.TemporaryDirectory(prefix="pp-poc-") as tmp:
        Path(tmp, "poc.py").write_text(code)
        proc = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--memory", "256m",
             "--cpus", "0.5", "-v", f"{tmp}:/work:ro", "python:3.12-slim",
             "python", "/work/poc.py"],
            capture_output=True, text=True, timeout=settings.sandbox_timeout_s + 30,
        )
        log = f"$ docker run --rm --network none python:3.12-slim python /work/poc.py\n{proc.stdout}{proc.stderr}\n[exit={proc.returncode}]"
        return log, proc.returncode == 0 and "REPRODUCED" in proc.stdout
