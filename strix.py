#!/usr/bin/env python3
"""
STRIX v3 — Silent Targeting · Recon · Intelligence · X-extractor
Autonomous bug-hunting engine: Recon -> CVE injection -> OWASP Top10:2025
-> AI triage -> Oracle validation (no noise) -> submission-ready report.

Single-file build. Deps: pip install httpx openai python-dotenv   (rich optional)

  python strix.py init
  python strix.py scan     -d example.com
  python strix.py recon    -d example.com
  python strix.py cve      -d example.com
  python strix.py owasp    -d example.com
  python strix.py triage   -d example.com
  python strix.py validate -d example.com
  python strix.py findings -d example.com -s confirmed
  python strix.py coverage -d example.com
  python strix.py report   -d example.com -o ./out
  python strix.py resume   -d example.com
  python strix.py alert-test
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import hashlib
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import ssl
import statistics
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------- optional deps
try:
    import httpx
except ImportError:
    print("FATAL: pip install httpx"); sys.exit(1)

try:
    from dotenv import load_dotenv
    for _p in ("configs/.env", ".env"):
        if Path(_p).exists():
            load_dotenv(_p); break
except Exception:
    pass

try:
    from rich.console import Console as _RC
    from rich.text import Text as _RT
    _RICH = True
except Exception:
    _RICH = False


# ================================================================ BRANDING
LOGO = r"""
   ███████╗████████╗██████╗ ██╗██╗  ██╗
   ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
   ███████╗   ██║   ██████╔╝██║ ╚███╔╝
   ╚════██║   ██║   ██╔══██╗██║ ██╔██╗
   ███████║   ██║   ██║  ██║██║██╔╝ ██╗
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
"""
TAGLINE = "S I L E N T   T A R G E T I N G  ·  R E C O N  ·  I N T E L L I G E N C E  ·  X - E X T R A C T O R"
VERSION = "3.0.0"

C = {"g": "\033[32m", "c": "\033[36m", "y": "\033[33m", "r": "\033[31m",
     "d": "\033[2m", "b": "\033[1m", "x": "\033[0m"}

def _p(msg):
    if _RICH:
        _RC().print(msg)
    else:
        print(re.sub(r"\[/?[a-z0-9 #_]+\]", "", str(msg)))

def banner():
    _p(f"[bold cyan]{LOGO}[/bold cyan]" if _RICH else f"{C['b']}{C['c']}{LOGO}{C['x']}")
    _p(f"  [dim]{TAGLINE}[/dim]" if _RICH else f"  {C['d']}{TAGLINE}{C['x']}")
    _p(f"  [bold white]v{VERSION}[/bold white] [dim]· OWASP Top10:2025 · Recon→CVE→Hunt→Validate→Report[/dim]"
       if _RICH else f"  {C['b']}v{VERSION}{C['x']} OWASP Top10:2025")
    _p("  " + "─" * 46)

def ok(m):   _p(f"[green]  ✔[/green] {m}" if _RICH else f"{C['g']}  ✔{C['x']} {m}")
def info(m): _p(f"[cyan]  ▸[/cyan] {m}" if _RICH else f"{C['c']}  ▸{C['x']} {m}")
def warn(m): _p(f"[yellow]  ▲[/yellow] {m}" if _RICH else f"{C['y']}  ▲{C['x']} {m}")
def bad(m):  _p(f"[red]  ✘[/red] {m}" if _RICH else f"{C['r']}  ✘{C['x']} {m}")
def step(n, t, m): _p(f"[bold cyan]  [{n}/{t}][/bold cyan] {m}" if _RICH else f"{C['b']}{C['c']}  [{n}/{t}]{C['x']} {m}")


# ================================================================ CONFIG
def _env(k, d=None): return os.environ.get(k, d)

@dataclass
class CFG:
    llm_backend: str = _env("STRIX_LLM_BACKEND", "openai")   # openai | ollama
    triage_model: str = _env("STRIX_TRIAGE_MODEL", "gpt-4o-mini")
    report_model: str = _env("STRIX_REPORT_MODEL", "gpt-4o")
    ollama_model: str = _env("STRIX_OLLAMA_MODEL", "qwen2.5:14b")
    llm_max_tokens: int = int(_env("STRIX_MAX_TOKENS", "2048"))
    proxy: str | None = _env("STRIX_PROXY")
    timeout: int = int(_env("STRIX_TIMEOUT", "20"))
    user_agent: str = _env("STRIX_UA", "Mozilla/5.0 (STRIX)")
    rps: int = int(_env("STRIX_RPS", "8"))
    cve_min_cvss: float = float(_env("STRIX_MIN_CVSS", "5.0"))
    cve_enrich: bool = _env("STRIX_CVE_ENRICH", "1") == "1"
    cve_allow_destructive: bool = _env("STRIX_ALLOW_DESTRUCTIVE", "0") == "1"
    oob_server: str = _env("STRIX_OOB_SERVER", "")
    timing_reps: int = int(_env("STRIX_TIMING_REPS", "9"))
    timing_factor: float = float(_env("STRIX_TIMING_FACTOR", "3.0"))
    ai_likely_threshold: float = float(_env("STRIX_LIKELY", "0.80"))
    min_score: float = float(_env("STRIX_MIN_SCORE", "0.45"))
    alert_backend: str = _env("STRIX_ALERT", "none")   # ntfy|discord|gotify|email|none

CFG = CFG()


# ================================================================ util.proc
def have(tool): return shutil.which(tool) is not None

def run(cmd, input_text=None, timeout=600):
    if not have(cmd[0]): return ""
    try:
        p = subprocess.run(cmd, input=input_text, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.stdout or ""
    except subprocess.TimeoutExpired:
        return ""

def lines(text): return [l.strip() for l in (text or "").splitlines() if l.strip()]


# ================================================================ util.http
_last = [0.0]
def _throttle():
    gap = 1.0 / max(1, CFG.rps)
    dt = time.time() - _last[0]
    if dt < gap: time.sleep(gap - dt)
    _last[0] = time.time()

def _client():
    return httpx.Client(proxies=CFG.proxy or None, timeout=CFG.timeout,
                        follow_redirects=True, verify=False,
                        headers={"User-Agent": CFG.user_agent})

def probe(url, method="GET", headers=None, body=None, params=None):
    _throttle()
    try:
        with _client() as c:
            t0 = time.time()
            r = c.request(method, url, headers=headers, content=body, params=params)
            return {"code": r.status_code, "len": len(r.content),
                    "time_ms": int((time.time() - t0) * 1000),
                    "headers": dict(r.headers), "body": r.text[:8000], "url": str(r.url)}
    except Exception as e:
        return {"code": 0, "len": 0, "time_ms": 0, "headers": {}, "body": f"ERR {e}", "url": url}

def time_only(url, params=None, method="GET", body=None):
    _throttle()
    try:
        with _client() as c:
            t0 = time.time(); c.request(method, url, params=params, content=body)
            return int((time.time() - t0) * 1000)
    except Exception:
        return -1


# ================================================================ util.alert
def send_alert(msg, severity="INFO"):
    b = CFG.alert_backend
    if b == "none": return
    try:
        if b == "ntfy":
            httpx.post(_env("NTFY_URL", ""), content=msg.encode(),
                       headers={"Title": f"STRIX [{severity}]"}, timeout=10)
        elif b == "discord":
            httpx.post(_env("DISCORD_WEBHOOK", ""), json={"content": msg}, timeout=10)
        elif b == "gotify":
            httpx.post(f'{_env("GOTIFY_URL","")}/message',
                       params={"token": _env("GOTIFY_TOKEN", "")},
                       data={"title": f"STRIX [{severity}]", "message": msg}, timeout=10)
        elif b == "email":
            subprocess.run(["msmtp", _env("ALERT_EMAIL", "")],
                           input=f"Subject: STRIX [{severity}]\n\n{msg}".encode())
    except Exception:
        pass


# ================================================================ MODELS
@dataclass
class Technology:
    endpoint: str
    product: str
    version: str | None = None
    cpe: str | None = None
    confidence: float = 0.5

@dataclass
class CVERecord:
    cve_id: str
    product: str
    version: str | None = None
    cvss: float = 0.0
    severity: str = "UNKNOWN"
    description: str = ""
    references: list = field(default_factory=list)
    cpe: str | None = None
    has_nuclei_template: bool = False
    exploitability_note: str = ""
    probe: dict | None = None
    injected: bool = False

@dataclass
class Finding:
    scan_id: int
    type: str
    endpoint: str
    owasp: str = ""
    cwe: str = ""
    param: str | None = None
    cve_id: str | None = None
    evidence: dict = field(default_factory=dict)
    ai_verdict: dict = field(default_factory=dict)
    status: str = "candidate"
    poc: str = ""
    severity: str = "INFO"
    score: float = 0.0
    confirmed_by: str = ""
    report: dict = field(default_factory=dict)
    id: int | None = None


# ================================================================ STORE
SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, root TEXT, created REAL, status TEXT DEFAULT 'running');
CREATE TABLE IF NOT EXISTS entities(
  id INTEGER PRIMARY KEY, scan_id INT, kind TEXT, value TEXT,
  status TEXT DEFAULT 'new', meta TEXT DEFAULT '{}',
  UNIQUE(scan_id, kind, value));
CREATE TABLE IF NOT EXISTS tech(
  id INTEGER PRIMARY KEY, scan_id INT, endpoint TEXT, product TEXT, version TEXT,
  cpe TEXT, confidence REAL, UNIQUE(scan_id, endpoint, product));
CREATE TABLE IF NOT EXISTS cves(
  id INTEGER PRIMARY KEY, scan_id INT, cve_id TEXT, product TEXT, version TEXT,
  cvss REAL, severity TEXT, description TEXT, references TEXT, cpe TEXT,
  has_nuclei INT, exploitability_note TEXT, probe TEXT, injected INT DEFAULT 0,
  UNIQUE(scan_id, cve_id, product));
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, scan_id INT, type TEXT, owasp TEXT, cwe TEXT,
  endpoint TEXT, param TEXT, cve_id TEXT, evidence TEXT, ai_verdict TEXT,
  status TEXT DEFAULT 'candidate', poc TEXT, severity TEXT, score REAL,
  confirmed_by TEXT, report TEXT,
  UNIQUE(scan_id, type, endpoint, param, cve_id));
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE INDEX IF NOT EXISTS ix_ent ON entities(scan_id, status);
CREATE INDEX IF NOT EXISTS ix_fnd ON findings(scan_id, status);
"""

class Store:
    _s = None
    def __new__(cls, db="state.db"):
        if cls._s is None:
            cls._s = super().__new__(cls); cls._s._init(db)
        return cls._s
    def _init(self, db):
        self.db = str(db)
        self.c = sqlite3.connect(self.db, check_same_thread=False)
        self.c.row_factory = sqlite3.Row
        self.c.executescript(SCHEMA); self.c.commit()

    def new_scan(self, root):
        cur = self.c.execute("INSERT INTO scans(root,created) VALUES(?,?)", (root, time.time()))
        self.c.commit(); return cur.lastrowid
    def scan_root(self, sid):
        r = self.c.execute("SELECT root FROM scans WHERE id=?", (sid,)).fetchone()
        return r["root"] if r else ""
    def scan_status(self, sid, st):
        self.c.execute("UPDATE scans SET status=? WHERE id=?", (st, sid)); self.c.commit()
    def latest_scan(self, root):
        r = self.c.execute("SELECT id FROM scans WHERE root=? ORDER BY id DESC LIMIT 1", (root,)).fetchone()
        return r["id"] if r else None

    def add_entity(self, sid, kind, value, status="new", **meta):
        self.c.execute("INSERT OR IGNORE INTO entities(scan_id,kind,value,status,meta) VALUES(?,?,?,?,?)",
                       (sid, kind, value, status, json.dumps(meta))); self.c.commit()
    def add_entities(self, sid, kind, values):
        self.c.executemany("INSERT OR IGNORE INTO entities(scan_id,kind,value) VALUES(?,?,?)",
                           [(sid, kind, v) for v in values if v]); self.c.commit()
    def entities(self, sid, kind, status=None):
        q = "SELECT * FROM entities WHERE scan_id=? AND kind=?"; a = [sid, kind]
        if status: q += " AND status=?"; a.append(status)
        return [dict(r) for r in self.c.execute(q, a).fetchall()]

    def add_tech(self, sid, t: Technology):
        self.c.execute("INSERT OR REPLACE INTO tech(scan_id,endpoint,product,version,cpe,confidence) VALUES(?,?,?,?,?,?)",
                       (sid, t.endpoint, t.product, t.version, t.cpe, t.confidence)); self.c.commit()
    def technologies(self, sid):
        return [Technology(endpoint=r["endpoint"], product=r["product"], version=r["version"],
                           cpe=r["cpe"], confidence=r["confidence"] or 0.5)
                for r in self.c.execute("SELECT * FROM tech WHERE scan_id=?", (sid,)).fetchall()]

    def save_cve(self, sid, c: CVERecord):
        self.c.execute("""INSERT OR REPLACE INTO cves
          (scan_id,cve_id,product,version,cvss,severity,description,references,cpe,
           has_nuclei,exploitability_note,probe,injected) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (sid, c.cve_id, c.product, c.version, c.cvss, c.severity, c.description,
           json.dumps(c.references), c.cpe, int(c.has_nuclei_template),
           c.exploitability_note, json.dumps(c.probe), int(c.injected))); self.c.commit()
    def cves(self, sid, injected_only=False):
        q = "SELECT * FROM cves WHERE scan_id=?" + (" AND injected=0" if injected_only else "")
        return [CVERecord(cve_id=r["cve_id"], product=r["product"], version=r["version"],
                cvss=r["cvss"] or 0, severity=r["severity"] or "UNKNOWN",
                description=r["description"] or "", references=json.loads(r["references"] or "[]"),
                cpe=r["cpe"], has_nuclei_template=bool(r["has_nuclei"]),
                exploitability_note=r["exploitability_note"] or "",
                probe=json.loads(r["probe"]) if r["probe"] else None,
                injected=bool(r["injected"]))
                for r in self.c.execute(q, (sid,)).fetchall()]
    def mark_cve_injected(self, sid, cve_id, product):
        self.c.execute("UPDATE cves SET injected=1 WHERE scan_id=? AND cve_id=? AND product=?",
                       (sid, cve_id, product)); self.c.commit()

    def save_finding(self, f: Finding) -> int:
        cur = self.c.execute("""INSERT OR REPLACE INTO findings
          (scan_id,type,owasp,cwe,endpoint,param,cve_id,evidence,ai_verdict,status,poc,
           severity,score,confirmed_by,report) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (f.scan_id, f.type, f.owasp, f.cwe, f.endpoint, f.param, f.cve_id,
           json.dumps(f.evidence), json.dumps(f.ai_verdict), f.status, f.poc,
           f.severity, f.score, f.confirmed_by, json.dumps(f.report)))
        self.c.commit(); return cur.lastrowid
    def findings(self, sid, status=None):
        q = "SELECT * FROM findings WHERE scan_id=?"; a = [sid]
        if status: q += " AND status=?"; a.append(status)
        out = []
        for r in self.c.execute(q, a).fetchall():
            out.append(Finding(scan_id=r["scan_id"], type=r["type"], owasp=r["owasp"] or "",
                cwe=r["cwe"] or "", endpoint=r["endpoint"], param=r["param"], cve_id=r["cve_id"],
                evidence=json.loads(r["evidence"] or "{}"), ai_verdict=json.loads(r["ai_verdict"] or "{}"),
                status=r["status"], poc=r["poc"] or "", severity=r["severity"] or "INFO",
                score=r["score"] or 0.0, confirmed_by=r["confirmed_by"] or "",
                report=json.loads(r["report"] or "{}"), id=r["id"]))
        return out
    def set_finding_status(self, fid, status, **report):
        row = self.c.execute("SELECT report FROM findings WHERE id=?", (fid,)).fetchone()
        rep = json.loads(row["report"] or "{}") if row else {}
        rep.update({k: v for k, v in report.items() if v is not None})
        sets, args = "status=?, report=?", [status, json.dumps(rep)]
        if report.get("score") is not None: sets += ", score=?"; args.append(report["score"])
        if report.get("confirmed_by") is not None: sets += ", confirmed_by=?"; args.append(report["confirmed_by"])
        if report.get("owasp") is not None: sets += ", owasp=?"; args.append(report["owasp"])
        if report.get("cwe") is not None: sets += ", cwe=?"; args.append(report["cwe"])
        args.append(fid)
        self.c.execute(f"UPDATE findings SET {sets} WHERE id=?", args); self.c.commit()

    def kv_get(self, k):
        r = self.c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone(); return r["v"] if r else None
    def kv_set(self, k, v):
        self.c.execute("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", (k, v)); self.c.commit()

STORE = Store()


# ================================================================ LLM
class LLM:
    def _cache(self, model, system, user):
        k = "llm:" + hashlib.sha256((model + system + user).encode()).hexdigest()
        return STORE.kv_get(k), k
    def complete_json(self, system, user, model=None):
        model = model or CFG.triage_model
        cached, key = self._cache(model, system, user)
        if cached: return json.loads(cached)
        if CFG.llm_backend == "ollama":
            import ollama
            r = ollama.chat(model=CFG.ollama_model, format="json",
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                options={"temperature": 0})
            out = json.loads(r["message"]["content"])
        else:
            from openai import OpenAI
            r = OpenAI().chat.completions.create(model=model, temperature=0,
                max_tokens=CFG.llm_max_tokens, response_format={"type": "json_object"},
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
            out = json.loads(r.choices[0].message.content)
        STORE.kv_set(key, json.dumps(out)); return out
    def complete_text(self, system, user, model=None):
        model = model or CFG.report_model
        cached, key = self._cache(model, system, user)
        if cached: return cached
        if CFG.llm_backend == "ollama":
            import ollama
            r = ollama.chat(model=CFG.ollama_model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                options={"temperature": 0.2})
            out = r["message"]["content"]
        else:
            from openai import OpenAI
            r = OpenAI().chat.completions.create(model=model, temperature=0.2,
                max_tokens=CFG.llm_max_tokens,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
            out = r.choices[0].message.content
        STORE.kv_set(key, out); return out

LLM = LLM()


# ================================================================ OWASP TAXONOMY
@dataclass(frozen=True)
class Category:
    code: str; name: str; cwes: tuple; finder_keys: tuple

OWASP = {
 "A01": Category("A01","Broken Access Control",
    ("CWE-284","CWE-285","CWE-639","CWE-918","CWE-352","CWE-22"),
    ("idor","bac","forced_browsing","open_redirect","ssrf","csrf","path_traversal")),
 "A02": Category("A02","Security Misconfiguration",
    ("CWE-16","CWE-2","CWE-388","CWE-1004","CWE-116"),
    ("misconfig_header","dir_listing","debug_endpoint","cloud_metadata","exposed_admin",
     "cors","verbose_error","insecure_default")),
 "A03": Category("A03","Software Supply Chain Failures",
    ("CWE-1104","CWE-1395","CWE-1035","CWE-937","CWE-829"),
    ("cve","outdated_component","integrity_attr","unpinned_dep","typosquat")),
 "A04": Category("A04","Cryptographic Failures",
    ("CWE-327","CWE-326","CWE-330","CWE-295","CWE-311","CWE-319"),
    ("weak_tls","weak_cipher","cleartext","weak_jwt","insecure_random","sensitive_exposure")),
 "A05": Category("A05","Injection",
    ("CWE-79","CWE-89","CWE-78","CWE-94","CWE-917","CWE-1336","CWE-90","CWE-643"),
    ("xss","sqli","nosqli","cmdi","ssti","ldapi","xpathi","crlf","xxe","header_injection")),
 "A06": Category("A06","Insecure Design",
    ("CWE-209","CWE-256","CWE-501","CWE-522","CWE-799"),
    ("logic_flaw","rate_limit_missing","business_logic","no_account_lockout")),
 "A07": Category("A07","Authentication Failures",
    ("CWE-287","CWE-384","CWE-613","CWE-798","CWE-307","CWE-521"),
    ("jwt_alg_none","jwt_weak","oauth_redirect","oauth_state","oauth_pkce","weak_password",
     "session_fixation","no_lockout","weak_mfa","default_creds")),
 "A08": Category("A08","Software or Data Integrity Failures",
    ("CWE-502","CWE-345","CWE-353","CWE-426","CWE-494"),
    ("insecure_deser","integrity_check","untrusted_update","unsigned_artifact")),
 "A09": Category("A09","Security Logging & Alerting Failures",
    ("CWE-117","CWE-223","CWE-778","CWE-532"),
    ("logging_failure","log_injection","no_alerting","sensitive_log")),
 "A10": Category("A10","Mishandling of Exceptional Conditions",
    ("CWE-230","CWE-248","CWE-252","CWE-274","CWE-391","CWE-754","CWE-755"),
    ("unhandled_exception","fail_open","stack_trace","improper_error")),
}

def classify(ftype):
    for cat in OWASP.values():
        if ftype in cat.finder_keys: return cat
    return None

def mk(ftype, sid, **kw) -> Finding:
    c = classify(ftype)
    return Finding(scan_id=sid, type=ftype, owasp=(c.code if c else ""),
                   cwe=(c.cwes[0] if c else ""), **kw)


# ================================================================ CVE ENGINE
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _cpe(product, version):
    p = re.sub(r"[^a-z0-9._-]", "", (product or "").lower().replace(" ", "_"))
    v = (version or "*").replace(" ", "")
    return f"cpe:2.3:a:*:{p}:{v}:*:*:*:*:*:*:*"

async def _nvd_query(cl, params):
    key = _env("NVD_API_KEY"); h = {"apiKey": key} if key else {}
    for attempt in range(4):
        r = await cl.get(NVD, params=params, headers=h, timeout=40)
        if r.status_code == 200: return r.json()
        if r.status_code in (403, 429): await asyncio.sleep(2 ** attempt); continue
        return {}
    return {}

def _nvd_parse(data, product, version, cpe):
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        score, sev = 0.0, "UNKNOWN"
        m = cve.get("metrics", {})
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if m.get(k):
                cd = m[k][0].get("cvssData", {})
                score = cd.get("baseScore", 0.0)
                sev = cd.get("baseSeverity") or m[k][0].get("baseSeverity", "UNKNOWN"); break
        out.append({"cve_id": cve.get("id", ""), "description": desc, "cvss": float(score),
                    "severity": sev.upper(),
                    "references": [r["url"] for r in cve.get("references", [])][:8],
                    "product": product, "version": version, "cpe": cpe})
    return out

async def _cves_async(product, version):
    cpe = _cpe(product, version)
    cached = STORE.kv_get(f"nvd:{cpe}")
    if cached: return json.loads(cached)
    async with httpx.AsyncClient() as cl:
        data = await _nvd_query(cl, {"virtualMatchString": cpe, "resultsPerPage": 200})
        if not data:
            data = await _nvd_query(cl, {"keywordSearch": f"{product} {version or ''}".strip(),
                                         "resultsPerPage": 100})
    parsed = _nvd_parse(data, product, version, cpe)
    STORE.kv_set(f"nvd:{cpe}", json.dumps(parsed)); return parsed

def cves_for_product(product, version):
    return asyncio.run(_cves_async(product, version))

def has_nuclei_template(cve_id):
    if not have("nuclei"): return False
    return cve_id.lower() in run(["nuclei", "-id", cve_id, "-tl"], timeout=60).lower()

ENRICH_SYSTEM = """You are a CVE exploitation analyst. Given a technology, its version,
a CVE record and target context, output JSON:
{"exploitability":"low|medium|high","note":"<preconditions, auth needed>",
 "probe":{"method":"GET|POST","path":"<relative path>","headers":{},"body":null,
          "match":["<response substrings indicating the vuln>"]},"destructive":false}
The probe must be a SAFE non-destructive detection request. If no safe detection is
possible set "probe": null and explain in note. Respond ONLY with JSON."""

def match_technologies(sid):
    recs = []
    for t in STORE.technologies(sid):
        if not t.version: continue
        for r in cves_for_product(t.product, t.version):
            rec = CVERecord(cve_id=r["cve_id"], product=t.product, version=t.version,
                cvss=r["cvss"], severity=r["severity"], description=r["description"],
                references=r["references"], cpe=r["cpe"])
            if rec.cvss < CFG.cve_min_cvss: continue
            rec.has_nuclei_template = has_nuclei_template(rec.cve_id)
            STORE.save_cve(sid, rec); recs.append(rec)
    seen, out = set(), []
    for r in recs:
        if (r.cve_id, r.product) in seen: continue
        seen.add((r.cve_id, r.product)); out.append(r)
    return out

def enrich_cve(rec: CVERecord, endpoint: str) -> CVERecord:
    if not CFG.cve_enrich: return rec
    payload = {"product": rec.product, "version": rec.version, "cve_id": rec.cve_id,
               "cvss": rec.cvss, "severity": rec.severity,
               "description": rec.description[:1500], "endpoint": endpoint}
    try:
        out = LLM.complete_json(ENRICH_SYSTEM, json.dumps(payload))
        rec.exploitability_note = f'{out.get("exploitability","?")}: {out.get("note","")}'
        pr = out.get("probe")
        if pr and (not out.get("destructive", False) or CFG.cve_allow_destructive):
            rec.probe = pr
    except Exception as e:
        rec.exploitability_note = f"enrich failed: {e}"
    return rec

def _nuclei_run(endpoint, cve_id):
    if not have("nuclei"): return []
    out = run(["nuclei", "-u", endpoint, "-id", cve_id, "-jsonl", "-silent", "-nc",
               "-timeout", "10", "-no-interactsh"], timeout=180)
    hits = []
    for line in out.splitlines():
        try: hits.append(json.loads(line))
        except Exception: pass
    return hits

def _probe_test(endpoint, pr):
    path = pr.get("path", "/")
    url = path if path.startswith("http") else endpoint.rstrip("/") + "/" + path.lstrip("/")
    base = probe(endpoint)
    test = probe(url, method=pr.get("method", "GET"), headers=pr.get("headers") or None, body=pr.get("body"))
    matches = [m for m in (pr.get("match") or []) if m and m.lower() in (test["body"] or "").lower()]
    return {"baseline": base, "probe": test, "matched": matches, "url": url} if matches else None

def inject_cves(sid, endpoints):
    for rec in STORE.cves(sid, injected_only=True):
        rec = enrich_cve(rec, endpoints[0] if endpoints else "")
        if not rec.probe and not rec.has_nuclei_template:
            STORE.mark_cve_injected(sid, rec.cve_id, rec.product); continue
        for ep in endpoints:
            if rec.has_nuclei_template:
                for hit in _nuclei_run(ep, rec.cve_id):
                    STORE.save_finding(mk("cve", sid, endpoint=ep, cve_id=rec.cve_id,
                        evidence={"engine": "nuclei", "template": hit.get("template-id"),
                                  "matched_at": hit.get("matched-at"),
                                  "matched": [str(hit.get("template-id"))]},
                        severity=rec.severity, score=rec.cvss))
                continue
            if rec.probe:
                res = _probe_test(ep, rec.probe)
                if res:
                    STORE.save_finding(mk("cve", sid, endpoint=ep, cve_id=rec.cve_id,
                        evidence={"engine": "probe", "url": res["url"], "matched": res["matched"],
                                  "baseline": res["baseline"], "probe": res["probe"],
                                  "note": rec.exploitability_note},
                        severity=rec.severity, score=rec.cvss))
        STORE.mark_cve_injected(sid, rec.cve_id, rec.product)


# ================================================================ RECON
def recon_subdomains(sid, root):
    subs = set()
    subs.update(lines(run(["subfinder", "-d", root, "-silent"])))
    subs.update(lines(run(["amass", "enum", "-passive", "-d", root, "-silent"])))
    subs.update(lines(run(["assetfinder", "--subs-only", root])))
    try:
        r = httpx.get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=40)
        for row in r.json(): subs.update(row.get("name_value", "").split("\n"))
    except Exception: pass
    subs = {s.strip().lower().lstrip("*.") for s in subs if root in s}
    STORE.add_entities(sid, "subdomain", sorted(subs))
    return sorted(subs)

def recon_resolve(sid, subs):
    gen = lines(run(["dnsgen", "-"], input_text="\n".join(subs))) or subs
    resolved = lines(run(["puredns", "resolve", "-"], input_text="\n".join(gen))) \
            or lines(run(["dnsx", "-silent"], input_text="\n".join(gen)))
    STORE.add_entities(sid, "host", resolved)
    return resolved

def recon_probe(sid, hosts):
    out = run(["httpx", "-silent", "-json", "-title", "-tech-detect", "-favicon", "-jarm",
               "-status-code", "-no-color"], input_text="\n".join(hosts))
    live = []
    for line in out.splitlines():
        try: j = json.loads(line)
        except Exception: continue
        url = j.get("url")
        if not url: continue
        live.append(url)
        STORE.add_entity(sid, "endpoint", url, status="live", title=j.get("title"),
                         status_code=j.get("status_code"), tech=j.get("tech"), jarm=j.get("jarm"))
        for t in (j.get("tech") or []):
            prod = t if isinstance(t, str) else str(t)
            STORE.add_tech(sid, Technology(endpoint=url, product=prod, confidence=0.5))
    return live

def recon_crawl(sid, endpoints, root):
    urls = set(lines(run(["gau", "--threads", "10", root])))
    urls.update(lines(run(["waymore", "-i", root, "-mode", "U"])))
    urls.update(lines(run(["katana", "-list", "-", "-silent", "-headless", "-jc", "-kf", "all"],
                          input_text="\n".join(endpoints))))
    key = _env("URLSCAN_API_KEY")
    if key:
        try:
            r = httpx.get("https://urlscan.io/api/v1/search/", params={"q": f'page.domain:"{root}"'},
                          headers={"API-Key": key}, timeout=40)
            for x in r.json().get("results", []):
                urls.add(x["page"]["url"]); urls.update(x.get("lists", {}).get("urls", []))
        except Exception: pass
    urls = {u for u in urls if u.startswith("http")}
    STORE.add_entities(sid, "url", sorted(urls))
    return sorted(urls)

def recon_jsmine(sid, urls):
    js = [u for u in urls if ".js" in u.split("?")[0]]
    STORE.add_entities(sid, "js", js)
    STORE.add_entities(sid, "url", lines(run(["jsluice", "urls"], input_text="\n".join(js))))
    raw = run(["jsluice", "secrets"], input_text="\n".join(js))
    for line in raw.splitlines():
        try:
            j = json.loads(line)
            STORE.add_entity(sid, "path", j.get("url", ""), status="secret",
                             kind=j.get("kind"), data=str(j.get("data"))[:200])
        except Exception: pass
    return {"js": len(js)}

def recon_waf(sid, endpoint):
    out = run(["wafw00f", endpoint, "-a", "-f", "json"])
    STORE.add_entity(sid, "tech", endpoint, status="waf", meta=out[:500])
    return out

def recon_apischema(sid, endpoints):
    paths = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/api-docs", "/graphql"]
    found = []
    for ep in endpoints:
        for p in paths:
            r = probe(ep.rstrip("/") + p)
            if r["code"] == 200 and any(k in r["body"].lower() for k in ("swagger", "openapi", "\"data\"")):
                STORE.add_entity(sid, "path", r["url"], status="api_schema", kind=p); found.append(r["url"])
            if p == "/graphql" and r["code"] in (200, 400):
                g = probe(r["url"], method="POST", headers={"Content-Type": "application/json"},
                          body=json.dumps({"query": "{__schema{types{name}}}"}))
                if "__schema" in g["body"]:
                    STORE.add_entity(sid, "path", r["url"], status="graphql"); found.append(r["url"])
    return found


# ================================================================ HUNT: A01..A10
# ---- A01 Broken Access Control
SSRF_PAY = ["http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/", "http://127.0.0.1:80/"]
ID_PARAMS = ("id", "uid", "user", "user_id", "account", "order", "doc", "file", "pid", "num")
URL_PARAMS = ("url", "uri", "path", "file", "link", "src", "dest", "redirect", "next",
              "return", "callback", "proxy", "site", "target")
REDIR_PARAMS = ("next", "url", "redirect", "return", "continue", "dest", "callback", "r")

def _h_idor(sid, url, p, v):
    base = probe(url)
    for m in (str(random.randint(10000, 99999)), "1", "999999"):
        r = probe(url.replace(f"{p}={v}", f"{p}={m}"))
        if r["code"] == base["code"] == 200 and r["body"] != base["body"] and abs(r["len"] - base["len"]) > 30:
            STORE.save_finding(mk("idor", sid, endpoint=url, param=p,
                evidence={"baseline": base, "probe": r, "mutated": m}, severity="HIGH", score=7.5)); return

def _h_ssrf(sid, url, p):
    for pay in SSRF_PAY:
        r = probe(url.replace(f"{p}=", f"{p}={urllib.parse.quote(pay)}"))
        b = r["body"].lower()
        if any(s in b for s in ("ami-id", "instance-id", "computemetadata", "root:x:0:0")):
            STORE.save_finding(mk("ssrf", sid, endpoint=url, param=p,
                evidence={"probe": r, "payload": pay, "matched": ["metadata"]},
                severity="CRITICAL", score=9.1)); return

def _h_redir(sid, url, p):
    pay = "https://strix-canary.example/"
    r = probe(url.replace(f"{p}=", f"{p}={urllib.parse.quote(pay)}"))
    if r["url"].startswith("https://strix-canary.example"):
        STORE.save_finding(mk("open_redirect", sid, endpoint=url, param=p,
            evidence={"landed": r["url"]}, severity="MEDIUM", score=5.3))

def _h_traversal(sid, url, p):
    for pay in ("../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"):
        r = probe(url.replace(f"{p}=", f"{p}={pay}"))
        if "root:x:0:0" in r["body"]:
            STORE.save_finding(mk("path_traversal", sid, endpoint=url, param=p,
                evidence={"probe": r, "file_read": "/etc/passwd"}, severity="HIGH", score=7.5)); return

def hunt_access(sid):
    for u in [e["value"] for e in STORE.entities(sid, "url")][:800]:
        if "?" not in u: continue
        for p, v in urllib.parse.parse_qs(urllib.parse.urlparse(u).query).items():
            vl = v[0] if v else ""
            if p.lower() in ID_PARAMS and vl.isdigit(): _h_idor(sid, u, p, vl)
            if p.lower() in URL_PARAMS:
                _h_ssrf(sid, u, p); _h_redir(sid, u, p); _h_traversal(sid, u, p)
            if p.lower() in REDIR_PARAMS: _h_redir(sid, u, p)

# ---- A02 Security Misconfiguration
_DEBUG_PATHS = ["/debug", "/actuator", "/actuator/env", "/actuator/heapdump", "/.env",
                "/server-status", "/phpinfo.php"]
_MIS_SIGS = ("spring", "actuator", "phpinfo", "db_password", "heap", "environment")

def _h_headers(sid, url):
    r = probe(url)
    need = {"strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"}
    miss = [h for h in need if h not in {k.lower() for k in r["headers"]}]
    if len(miss) >= 3:
        STORE.save_finding(mk("misconfig_header", sid, endpoint=url,
            evidence={"headers": r["headers"], "missing": miss, "matched": miss},
            severity="MEDIUM", score=5.0))

def _h_exposure(sid, url):
    for p in _DEBUG_PATHS:
        r = probe(url.rstrip("/") + "/" + p.lstrip("/"))
        if r["code"] == 200 and any(s in r["body"].lower() for s in _MIS_SIGS):
            STORE.save_finding(mk("debug_endpoint", sid, endpoint=r["url"],
                evidence={"probe": r, "matched": [p]}, severity="HIGH", score=7.2))

def _h_dirlist(sid, url):
    r = probe(url)
    if "Index of /" in r["body"] or "Directory listing" in r["body"]:
        STORE.save_finding(mk("dir_listing", sid, endpoint=url,
            evidence={"probe": {"code": r["code"], "body": r["body"][:400]}, "matched": ["dirlist"]},
            severity="MEDIUM", score=5.0))

def hunt_misconfig(sid):
    for u in [e["value"] for e in STORE.entities(sid, "endpoint")][:400]:
        _h_headers(sid, u); _h_exposure(sid, u); _h_dirlist(sid, u)

# ---- A03 Supply Chain
def hunt_supplychain(sid):
    for e in STORE.entities(sid, "js") + STORE.entities(sid, "path", status="secret"):
        v = (e["value"] or "")
        if "cdn" in v.lower() and "integrity" not in (e.get("meta") or ""):
            STORE.save_finding(mk("integrity_attr", sid, endpoint=v,
                evidence={"matched": ["missing SRI"]}, severity="MEDIUM", score=5.0))

# ---- A04 Crypto
def _h_tls(sid, url):
    host = urllib.parse.urlparse(url).netloc.split(":")[0]
    try:
        with socket.create_connection((host, 443), timeout=8) as s:
            with ssl.create_default_context().wrap_socket(s, server_hostname=host) as ss:
                ver = ss.version()
                if ver in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
                    STORE.save_finding(mk("weak_tls", sid, endpoint=url,
                        evidence={"matched": [ver]}, severity="HIGH", score=7.0))
    except Exception: return

def _h_cleartext(sid, url):
    if url.startswith("http://") and "localhost" not in url:
        r = probe(url)
        if any(k in r["body"].lower() for k in ("password", "api_key", "authorization")):
            STORE.save_finding(mk("cleartext", sid, endpoint=url,
                evidence={"matched": ["credentials over HTTP"]}, severity="HIGH", score=7.5))

def hunt_crypto(sid):
    for u in [e["value"] for e in STORE.entities(sid, "endpoint")][:200]:
        _h_tls(sid, u) if u.startswith("https") else _h_cleartext(sid, u)

# ---- A05 Injection
_MARK = "strix7x9qz"
def _h_xss(sid, url, p):
    base = probe(url)
    pay = f"<img src=x onerror=alert({_MARK})>"
    r = probe(url.replace(f"{p}=", f"{p}={urllib.parse.quote(pay)}"))
    if _MARK in r["body"]:
        STORE.save_finding(mk("xss", sid, endpoint=url, param=p,
            evidence={"baseline": base, "probe": r, "payload": pay}, severity="HIGH", score=7.0))

def _h_sqli(sid, url, p):
    base = probe(url)
    inj = probe(url.replace(f"{p}=", f"{p}=1'", 1))
    errs = ("sql syntax", "mysql", "postgres", "ora-", "sqlite", "unclosed quotation", "syntax error")
    if any(e in inj["body"].lower() for e in errs):
        STORE.save_finding(mk("sqli", sid, endpoint=url, param=p,
            evidence={"baseline": base, "probe": inj, "payload": "'"}, severity="HIGH", score=8.0))

def _h_nosqli(sid, url, p):
    pay = "';return true;var x='"
    r = probe(url.replace(f"{p}=", f"{p}={urllib.parse.quote(pay)}"))
    if any(s in r["body"].lower() for s in ("mongo", "$where", "nosql")):
        STORE.save_finding(mk("nosqli", sid, endpoint=url, param=p,
            evidence={"probe": r, "payload": pay}, severity="HIGH", score=7.5))

def _h_ssti(sid, url, p):
    for pay, exp in (("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49")):
        r = probe(url.replace(f"{p}=", f"{p}={urllib.parse.quote(pay)}"))
        if exp in r["body"]:
            STORE.save_finding(mk("ssti", sid, endpoint=url, param=p,
                evidence={"probe": r, "payload": pay, "eval_result": exp, "expected": exp},
                severity="CRITICAL", score=8.8)); return

def _h_crlf(sid, url, p):
    pay = "%0d%0aStrix-Injected%3a%20yes"
    r = probe(url.replace(f"{p}=", f"{p}={pay}"))
    if "strix-injected" in {k.lower() for k in r["headers"]}:
        STORE.save_finding(mk("crlf", sid, endpoint=url, param=p,
            evidence={"headers": r["headers"], "payload": pay}, severity="MEDIUM", score=6.0))

def hunt_injection(sid):
    for u in [e["value"] for e in STORE.entities(sid, "url")][:800]:
        if "?" not in u: continue
        for p in urllib.parse.parse_qs(urllib.parse.urlparse(u).query):
            _h_xss(sid, u, p); _h_sqli(sid, u, p); _h_nosqli(sid, u, p)
            _h_ssti(sid, u, p); _h_crlf(sid, u, p)

# ---- A07 Auth (JWT / OAuth)
def _b64d(s):
    s += "=" * (-len(s) % 4); return json.loads(base64.urlsafe_b64decode(s.encode()))

def _h_jwt(sid, url, token):
    try:
        h, p, _ = token.split(".")
        if _b64d(h).get("alg", "").lower() == "none":
            STORE.save_finding(mk("jwt_alg_none", sid, endpoint=url,
                evidence={"matched": ["alg=none"], "token": h[:60]}, severity="CRITICAL", score=9.0))
        nh = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        forged = f"{nh}.{p}."
        base = probe(url); r = probe(url, headers={"Authorization": f"Bearer {forged}"})
        if r["code"] == 200 and base["code"] in (401, 403, 0):
            STORE.save_finding(mk("jwt_alg_none", sid, endpoint=url,
                evidence={"status_before": base["code"], "status_after": r["code"], "token": forged[:60]},
                severity="CRITICAL", score=9.2))
    except Exception: return

def _h_oauth(sid, url):
    q = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    if "redirect_uri" in q:
        orig = q["redirect_uri"][0]
        for evil in ("https://evil.example/", "https://evil.example@"):
            r = probe(url.replace(f"redirect_uri={urllib.parse.quote(orig)}",
                                  f"redirect_uri={urllib.parse.quote(evil)}"))
            if "evil.example" in json.dumps(r["headers"]):
                STORE.save_finding(mk("oauth_redirect", sid, endpoint=url,
                    evidence={"landed": r["headers"].get("location", ""), "payload": evil},
                    severity="HIGH", score=7.0))
    if "response_type" in q and "state" not in q:
        STORE.save_finding(mk("oauth_state", sid, endpoint=url,
            evidence={"matched": ["no state param"]}, severity="MEDIUM", score=5.5))

def hunt_auth(sid):
    urls = [e["value"] for e in STORE.entities(sid, "url")] + \
           [e["value"] for e in STORE.entities(sid, "endpoint")]
    for u in urls[:500]: _h_oauth(sid, u)
    for e in STORE.entities(sid, "path"):
        v = e["value"] or ""
        if v.count(".") == 2 and v[:2] == "ey": _h_jwt(sid, "(captured)", v)

# ---- A08 Integrity
def hunt_integrity(sid):
    for e in STORE.entities(sid, "url"):
        v = (e["value"] or "").lower()
        if any(s in v for s in ("pickle", "ysoserial", "java.io", "objectinputstream")):
            STORE.save_finding(mk("insecure_deser", sid, endpoint=e["value"],
                evidence={"matched": ["deser marker"]}, severity="HIGH", score=7.2))

# ---- A09 Logging
def hunt_logging(sid):
    for e in STORE.entities(sid, "endpoint"):
        r = probe(e["value"] + "/strix-not-found-" + "z" * 12)
        b = r["body"].lower()
        if r["code"] >= 500 and "request id" not in b and "trace" in b:
            STORE.save_finding(mk("logging_failure", sid, endpoint=e["value"],
                evidence={"probe": {"code": r["code"], "body": b[:300]}, "matched": ["trace"]},
                severity="LOW", score=3.5))

# ---- A10 Exceptions
_ERR_SIGS = ("stack trace", "traceback (most recent call last)", "at java.", "at org.springframework",
             "undefined index", "unhandled exception", "nullreferenceexception", "exception in thread")
def hunt_exceptions(sid):
    for e in STORE.entities(sid, "endpoint"):
        u = e["value"]
        for suf in ("?strix=[]", "?strix[=1", "?strix=%00", "/%00", "?a[0][1][2]=x"):
            r = probe(u.rstrip("/") + suf); b = r["body"].lower()
            hit = [s for s in _ERR_SIGS if s in b]
            if hit:
                STORE.save_finding(mk("unhandled_exception", sid, endpoint=u,
                    evidence={"probe": {"code": r["code"], "body": r["body"][:400]},
                              "error_sig": hit, "matched": hit}, severity="MEDIUM", score=5.5)); break

def owasp_run_all(sid, progress=None):
    runners = [("A01", hunt_access), ("A02", hunt_misconfig), ("A03", hunt_supplychain),
               ("A04", hunt_crypto), ("A05", hunt_injection), ("A07", hunt_auth),
               ("A08", hunt_integrity), ("A09", hunt_logging), ("A10", hunt_exceptions)]
    counts = {}
    for code, fn in runners:
        try:
            fn(sid); counts[code] = "ok"
            if progress: progress(code)
        except Exception as e:
            counts[code] = f"err:{e}"
    return counts


# ================================================================ TRIAGE
TRIAGE_SYSTEM = """You are a precise bug-bounty triage engine. You receive ONE candidate
finding as JSON with baseline and probe responses. Decide if it is a REAL vulnerability.

HARD RULES:
- Cite a specific artifact from baseline/probe (error string, timing delta, reflected
  token, ACAO header, body diff) in "evidence_cited". Quote it.
- If no concrete artifact exists, return {"verdict": false, ...}.
- Judge only from supplied evidence. Provide concrete "next_test" and a copy-paste curl "poc".
Output ONLY JSON: {"verdict":bool,"confidence":0..1,"class":str,"evidence_cited":str,"next_test":str,"poc":str}"""

def _triage_payload(f):
    ev = f.evidence
    return {"type": f.type, "endpoint": f.endpoint, "param": f.param, "cve_id": f.cve_id,
            "baseline": ev.get("baseline"), "probe": ev.get("probe"),
            "matched": ev.get("matched") or ev.get("error_sig") or ev.get("file_read"),
            "tool": ev.get("engine"), "severity_hint": f.severity,
            "extra": {k: v for k, v in ev.items() if k not in ("baseline", "probe")}}

def hunt_triage(sid):
    for f in STORE.findings(sid, status="candidate"):
        if f.type == "cve" and f.evidence.get("engine") == "nuclei":
            continue
        try:
            v = LLM.complete_json(TRIAGE_SYSTEM, json.dumps(_triage_payload(f)))
            f.ai_verdict = {"verdict": bool(v.get("verdict")), "confidence": float(v.get("confidence", 0)),
                            "class": v.get("class", ""), "evidence_cited": v.get("evidence_cited", ""),
                            "next_test": v.get("next_test", "")}
            if v.get("poc"): f.poc = v["poc"]
            if not v.get("verdict"):
                STORE.set_finding_status(f.id, "rejected", reason=v.get("evidence_cited", "ai-rejected"))
            else:
                cat = classify(f.type)
                STORE.set_finding_status(f.id, "candidate",
                    reason=v.get("evidence_cited", ""), next_test=v.get("next_test", ""),
                    ai_confidence=float(v.get("confidence", 0)),
                    owasp=(cat.code if cat else None), cwe=(cat.cwes[0] if cat else None))
                STORE.save_finding(f)
        except Exception as e:
            STORE.set_finding_status(f.id, "rejected", reason=f"triage error: {e}")

def _poc_curl(f):
    ev = f.evidence
    if f.type == "cve" and ev.get("engine") == "probe":
        pat = "|".join(ev.get("matched", [])) or "CVE"
        return f"curl -sk '{ev['url']}' -o - | grep -Ei '{pat}'"
    if f.type in ("sqli", "xss", "ssti") and f.param:
        sep = "&" if "?" in f.endpoint else "?"
        pay = {"sqli": "%27", "xss": "strix7x9qz", "ssti": "%7B%7B7*7%7D%7D"}[f.type]
        return f"curl -sk '{f.endpoint}{sep}{f.param}={pay}' -o -"
    if f.type == "open_redirect":
        sep = "&" if "?" in f.endpoint else "?"
        return f"curl -sk -I '{f.endpoint}{sep}next=https://strix-canary.example/'"
    if f.type in ("idor", "bac") and f.param:
        return (f"curl -sk '{f.endpoint}' -o - | diff - "
                f"<(curl -sk '{f.endpoint.replace(f.param+'=', f.param+'=2')}' -o -)")
    return f"curl -sk '{f.endpoint}' -o -"

def hunt_poc(sid):
    for f in STORE.findings(sid):
        if f.status == "rejected": continue
        if not f.poc: f.poc = _poc_curl(f)
        if f.id: STORE.save_finding(f)


# ================================================================ ORACLES
def confirm_oob(oob_server, token):
    if not oob_server or not token: return False
    try:
        return bool(httpx.get(f"http://{oob_server}/poll", params={"id": token}, timeout=10).json().get("data"))
    except Exception: return False

def confirm_diff(baseline, mutant):
    if baseline.get("code") == mutant.get("code") == 200:
        return (baseline.get("body") != mutant.get("body")
                and len(mutant.get("body", "")) > 0
                and abs(baseline.get("len", 0) - mutant.get("len", 0)) > 20)
    return False

def confirm_cors(headers): return headers.get("access-control-allow-origin") == "https://evil.example"
def confirm_redirect(u): return u.startswith("https://strix-canary.example") or u.startswith("https://evil.example")

def confirm_timing(url, base_params, inj_params, reps=9, factor=3.0):
    base = [t for t in (time_only(url, params=base_params) for _ in range(reps)) if t >= 0]
    inj = [t for t in (time_only(url, params=inj_params) for _ in range(reps)) if t > 0]
    if not base or not inj: return False
    return statistics.median(inj) > factor * max(1, statistics.median(base))

def confirm_xss_reflection(body, payload):
    if not payload or payload not in body: return False
    i = body.find(payload); ctx = body[max(0, i - 60):i]
    return not ("&lt;" in ctx or "&gt;" in ctx)


# ================================================================ VALIDATOR (no noise)
REQUIREMENTS = {
  "xss": "reflection", "sqli": "timing", "nosqli": "error_sig", "ssti": "eval_math",
  "ssrf": "oob", "path_traversal": "file_marker", "idor": "diff", "bac": "diff",
  "cors": "header", "open_redirect": "redirect", "crlf": "header_inj",
  "jwt_alg_none": "auth_bypass", "oauth_redirect": "redirect", "cve": "signature",
  "unhandled_exception": "error_sig",
}

def _fp(f):
    ep = re.sub(r"(https?://[^/]+).*", r"\1", f.endpoint)
    return hashlib.sha256(f"{f.type}|{ep}|{f.param or ''}".encode()).hexdigest()

def _has_artifact(f):
    ev = f.evidence or {}
    return any(ev.get(k) for k in ("matched", "error_sig", "delta", "landed", "token",
                                   "file_read", "headers", "probe", "baseline", "eval_result"))

def _oracle(f):
    ev = f.evidence or {}
    o = REQUIREMENTS.get(f.type)
    try:
        if o == "reflection":
            return confirm_xss_reflection((ev.get("probe") or {}).get("body", ""), ev.get("payload", ""))
        if o == "timing":
            return confirm_timing(f.endpoint, {f.param: "1"}, {f.param: "1 AND SLEEP(5)"},
                                  CFG.timing_reps, CFG.timing_factor)
        if o == "oob":
            return confirm_oob(CFG.oob_server, ev.get("token", ""))
        if o == "diff":
            return confirm_diff(ev.get("baseline", {}), ev.get("probe", {}))
        if o == "header":
            return confirm_cors(ev.get("headers", {}))
        if o == "redirect":
            return confirm_redirect(ev.get("landed", ""))
        if o == "file_marker":
            return "root:x:0:0" in (ev.get("probe", {}).get("body", ""))
        if o == "eval_math":
            return ev.get("eval_result") == ev.get("expected")
        if o == "signature":
            return bool(ev.get("matched")) or ev.get("engine") == "nuclei"
        if o == "auth_bypass":
            return ev.get("status_after") == 200 and ev.get("status_before") in (401, 403, 0)
        if o == "error_sig":
            return bool(ev.get("matched") or ev.get("error_sig"))
        if o == "header_inj":
            return any("strix-injected" in k.lower() for k in ev.get("headers", {}))
    except Exception:
        return None
    return None

def _score(f, confirmed):
    s = (0.6 if confirmed else 0.0) + 0.4 * float((f.ai_verdict or {}).get("confidence", 0))
    sev = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.55, "LOW": 0.3, "INFO": 0.1}.get(f.severity, 0.1)
    return round(min(0.7 * s + 0.3 * sev, 1.0), 3)

def validate(sid):
    seen, stats = {}, {"dropped_no_evidence": 0, "confirmed": 0, "likely": 0, "rejected": 0, "deduped": 0}
    for f in STORE.findings(sid, status="candidate"):
        if f.type != "cve" and not _has_artifact(f):
            STORE.set_finding_status(f.id, "rejected", reason="no concrete artifact")
            stats["dropped_no_evidence"] += 1; continue
        verdict = _oracle(f)
        if verdict is True: status = "confirmed"
        elif verdict is False and f.type != "cve": status = "rejected"
        else:
            conf = float((f.ai_verdict or {}).get("confidence", 0))
            v = bool((f.ai_verdict or {}).get("verdict"))
            status = "likely" if (v and conf >= CFG.ai_likely_threshold) else "rejected"
        f.status = status; f.score = _score(f, status == "confirmed")
        fp = _fp(f); cat = classify(f.type)
        meta = {"score": f.score, "owasp": cat.code if cat else "", "cwe": cat.cwes[0] if cat else "",
                "confirmed_by": "oracle" if status == "confirmed" else ""}
        if fp in seen:
            keep, drop = (f, seen[fp]) if f.score > seen[fp].score else (seen[fp], f)
            STORE.set_finding_status(drop.id, "rejected", reason="duplicate")
            stats["deduped"] += 1; seen[fp] = keep; continue
        seen[fp] = f
        STORE.set_finding_status(f.id, status, **meta)
        stats[status] += 1
    return stats

def prune_low_signal(sid, min_score=None):
    min_score = CFG.min_score if min_score is None else min_score
    moved = 0
    for f in STORE.findings(sid, status="confirmed"):
        if f.score < min_score:
            STORE.set_finding_status(f.id, "likely", reason=f"low signal ({f.score})"); moved += 1
    return moved

def validate_all(sid):
    stats = validate(sid)
    stats["pruned"] = prune_low_signal(sid)
    return stats


# ================================================================ AUTOPILOT
def autopilot(sid):
    for f in STORE.findings(sid, status="candidate"):
        ev, status = f.evidence, None
        try:
            if ev.get("engine") == "nuclei" or (f.type == "cve" and ev.get("matched")):
                status = "confirmed"
            elif f.type == "xss":
                status = "confirmed" if confirm_xss_reflection(
                    (ev.get("probe") or {}).get("body", ""), ev.get("payload", "")) else None
            elif f.type == "sqli":
                status = "confirmed" if confirm_timing(f.endpoint, {f.param: "1"},
                    {f.param: "1 AND SLEEP(5)"}, CFG.timing_reps, CFG.timing_factor) else None
        except Exception:
            status = None
        if status is None:
            conf = float((f.ai_verdict or {}).get("confidence", 0))
            v = bool((f.ai_verdict or {}).get("verdict"))
            status = "likely" if (v and conf >= CFG.ai_likely_threshold) else "rejected"
        STORE.set_finding_status(f.id, status,
            confirmed_by=("oracle" if status == "confirmed" else "ai" if status == "likely" else "none"))


# ================================================================ REPORT
NARRATIVE_SYSTEM = """You write bug-bounty reports. Given a confirmed finding as JSON, produce
Markdown with: Impact, Steps to Reproduce, Evidence, Remediation (CWE/OWASP where relevant).
Be concise and factual. Do not invent details not present in the evidence."""

def build_report(sid, outdir="."):
    conf = STORE.findings(sid, status="confirmed")
    likely = STORE.findings(sid, status="likely")
    counts = {}
    for f in conf:
        cat = classify(f.type); code = cat.code if cat else ""
        f.owasp, f.cwe = code, (cat.cwes[0] if cat else "")
        STORE.set_finding_status(f.id, "confirmed", owasp=code, cwe=f.cwe)
        counts[code] = counts.get(code, 0) + 1
    narr = {}
    for f in conf:
        try: narr[f.id] = LLM.complete_text(NARRATIVE_SYSTEM, json.dumps(asdict(f), default=str))
        except Exception: narr[f.id] = "(narrative unavailable)"
    target = STORE.scan_root(sid)
    gen = datetime.datetime.utcnow().isoformat() + "Z"

    md = [f"# STRIX Security Assessment\n_Target: {target} · Generated {gen} · Standard: OWASP Top 10:2025_\n",
          "## Executive Summary",
          f"- Confirmed findings: **{len(conf)}**",
          f"- Human-review (likely): **{len(likely)}**\n",
          "## OWASP Top 10:2025 Coverage",
          "| Code | Category | Findings |", "|------|----------|----------|"]
    for code, cat in OWASP.items():
        md.append(f"| {code} | {cat.name} | {counts.get(code, 0)} |")
    md.append("---\n## Confirmed Findings")
    for f in conf:
        md.append(f"### [{f.owasp or '--'}][{f.severity}] {f.type.upper()}"
                  + (f" — {f.cve_id}" if f.cve_id else ""))
        md.append(f"- **Endpoint:** `{f.endpoint}`" + (f" · **Param:** `{f.param}`" if f.param else ""))
        md.append(f"- **CWE:** {f.cwe or 'n/a'} · **Score:** {f.score:.2f} · **Confirmed by:** {f.confirmed_by}")
        md.append("\n**Proof of Concept**\n```bash\n" + f.poc + "\n```")
        md.append(narr.get(f.id, ""))
        md.append("---")
    md.append("## Likely — Human Review")
    for f in likely:
        md.append(f"- [{f.severity}] `{f.type}` @ `{f.endpoint}`")
    markdown = "\n".join(md)

    rows = "".join(f"<tr><td>{c}</td><td>{cat.name}</td><td>{counts.get(c,0)}</td></tr>"
                   for c, cat in OWASP.items())
    fsec = ""
    for f in conf:
        fsec += (f'<h3><span class="sev {f.severity}">{f.severity}</span> {f.owasp} '
                 f'{f.type.upper()} {f.cve_id or ""}</h3>'
                 f'<p><b>Endpoint:</b> <code>{f.endpoint}</code> · <b>CWE:</b> {f.cwe} '
                 f'· <b>Score:</b> {f.score:.2f}</p><pre>{f.poc}</pre>'
                 f'<div>{narr.get(f.id,"").replace(chr(10), "<br>")}</div><hr>')
    lsec = "".join(f"<li><b>{f.severity}</b> {f.type} @ <code>{f.endpoint}</code></li>" for f in likely)
    html = f"""<!doctype html><meta charset=utf-8><title>STRIX — {target}</title>
<style>body{{font:14px/1.55 system-ui;max-width:960px;margin:2rem auto;padding:0 1rem;color:#111}}
h2{{border-bottom:1px solid #ddd;padding-bottom:.3rem}}code,pre{{background:#f5f5f5;padding:.25rem .5rem;border-radius:5px}}
.sev{{display:inline-block;padding:2px 9px;border-radius:10px;color:#fff;font-size:12px}}
.CRITICAL{{background:#7f1d1d}}.HIGH{{background:#b91c1c}}.MEDIUM{{background:#b45309}}.LOW{{background:#166534}}.INFO{{background:#374151}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:4px 8px;text-align:left}}</style>
<h1>STRIX Security Assessment</h1>
<p><b>Target:</b> {target} · <b>Generated:</b> {gen} · <b>Standard:</b> OWASP Top 10:2025</p>
<h2>Executive Summary</h2><p>Confirmed: <b>{len(conf)}</b> · Human-review: <b>{len(likely)}</b></p>
<h2>OWASP Top 10:2025 Coverage</h2><table><tr><th>Code</th><th>Category</th><th>Findings</th></tr>{rows}</table>
<h2>Confirmed Findings</h2>{fsec}<h2>Likely — Human Review</h2><ul>{lsec}</ul>"""

    Path(outdir).mkdir(parents=True, exist_ok=True)
    Path(outdir, "report.md").write_text(markdown)
    Path(outdir, "report.html").write_text(html)
    return len(conf), len(likely)


# ================================================================ PIPELINE
def full_scan(domain, skip_cve=False):
    banner(); sid = STORE.new_scan(domain); info(f"scan #{sid} → {domain}"); T = 6
    step(1, T, "RECON")
    subs = recon_subdomains(sid, domain); hosts = recon_resolve(sid, subs)
    live = recon_probe(sid, hosts); urls = recon_crawl(sid, live, domain)
    recon_jsmine(sid, urls); recon_apischema(sid, live)
    if live: recon_waf(sid, live[0])
    info(f"subs={len(subs)} live={len(live)} urls={len(urls)}")
    if not skip_cve:
        step(2, T, "CVE ENGINE")
        recs = match_technologies(sid)
        info(f"matched {len(recs)} CVEs (cvss≥{CFG.cve_min_cvss})"); inject_cves(sid, live)
    step(3, T, "OWASP A01–A10 DETECTION")
    owasp_run_all(sid, progress=lambda c: info(f"{c} done"))
    step(4, T, "AI TRIAGE + PoC")
    hunt_triage(sid); hunt_poc(sid)
    info(f"candidates={len(STORE.findings(sid, status='candidate'))}")
    step(5, T, "VALIDATE + DE-NOISE"); stats = validate_all(sid)
    info(f"confirmed={stats['confirmed']} likely={stats['likely']} dropped={stats['dropped_no_evidence']} "
         f"deduped={stats['deduped']} pruned={stats['pruned']}")
    step(6, T, "REPORT"); n, l = build_report(sid)
    STORE.scan_status(sid, "done")
    send_alert(f"STRIX #{sid} {domain}: {n} confirmed / {l} likely", "HIGH")
    ok(f"done → report.html ({n} confirmed, {l} likely)")


# ================================================================ CLI
def main():
    ap = argparse.ArgumentParser(prog="strix", description="STRIX v3 — autonomous OWASP Top10:2025 bug-hunting engine")
    sub = ap.add_subparsers(dest="cmd")

    def add(name, help_):
        p = sub.add_parser(name, help=help_)
        p.add_argument("-d", "--domain", required=True)
        return p

    sub.add_parser("init", help="initialise state.db and verify tooling")
    p = add("scan", "FULL pipeline")
    p.add_argument("--skip-cve", action="store_true")
    add("recon", "phase 1 only — attack-surface mapping")
    add("cve", "CVE match + injection")
    add("owasp", "OWASP A01–A10 detection + validate")
    add("triage", "LLM triage + PoC")
    add("validate", "validator + noise pruner")
    p = add("findings", "list findings by status")
    p.add_argument("-s", "--status", default="confirmed")
    add("coverage", "OWASP coverage matrix")
    p = add("report", "generate submission-ready report")
    p.add_argument("-o", "--out", default=".")
    add("resume", "resume latest scan")
    sub.add_parser("alert-test", help="send a test alert")

    a = ap.parse_args()
    if not a.cmd:
        banner(); ap.print_help(); return

    if a.cmd == "init":
        banner()
        for t in ("subfinder", "httpx", "katana", "nuclei", "gau", "ffuf", "jsluice", "interactsh-client"):
            (ok if have(t) else warn)(f"tool: {t}")
        ok("state.db ready")
    elif a.cmd == "scan":
        full_scan(a.domain, a.skip_cve)
    elif a.cmd == "recon":
        banner(); sid = STORE.new_scan(a.domain)
        subs = recon_subdomains(sid, a.domain); hosts = recon_resolve(sid, subs)
        live = recon_probe(sid, hosts); urls = recon_crawl(sid, live, a.domain)
        recon_jsmine(sid, urls); recon_apischema(sid, live)
        ok(f"recon done #{sid}: subs={len(subs)} live={len(live)} urls={len(urls)}")
    elif a.cmd == "cve":
        banner(); sid = STORE.latest_scan(a.domain) or STORE.new_scan(a.domain)
        match_technologies(sid)
        inject_cves(sid, [e["value"] for e in STORE.entities(sid, "endpoint")])
        for c in STORE.cves(sid):
            ok(f"{c.cve_id} cvss={c.cvss} {c.product} {c.version} "
               f"[{'nuclei' if c.has_nuclei_template else 'probe' if c.probe else 'no-test'}]")
    elif a.cmd == "owasp":
        banner(); sid = STORE.latest_scan(a.domain) or STORE.new_scan(a.domain)
        owasp_run_all(sid); hunt_triage(sid); hunt_poc(sid)
        ok(f"owasp: {validate_all(sid)}")
    elif a.cmd == "triage":
        banner(); sid = STORE.latest_scan(a.domain); hunt_triage(sid); hunt_poc(sid); ok("triage done")
    elif a.cmd == "validate":
        banner(); sid = STORE.latest_scan(a.domain); ok(str(validate_all(sid)))
        for f in STORE.findings(sid, status="confirmed"):
            ok(f"[{f.owasp or '--'}] {f.severity:8} {f.type:18} {f.endpoint}")
    elif a.cmd == "findings":
        banner(); sid = STORE.latest_scan(a.domain)
        for f in STORE.findings(sid, status=a.status):
            print(f"{f.owasp or '--':5} {f.severity:8} {f.type:18} score={f.score:.2f} {f.endpoint}")
    elif a.cmd == "coverage":
        banner(); sid = STORE.latest_scan(a.domain)
        hit = {f.owasp for f in STORE.findings(sid) if f.status in ("confirmed", "likely") and f.owasp}
        for code, cat in OWASP.items():
            ok(f"{code}  {'HIT ' if code in hit else '·   '} {cat.name}")
    elif a.cmd == "report":
        banner(); sid = STORE.latest_scan(a.domain); n, l = build_report(sid, a.out)
        ok(f"report → {a.out}/report.html ({n} confirmed, {l} likely)")
    elif a.cmd == "resume":
        banner(); sid = STORE.latest_scan(a.domain)
        owasp_run_all(sid); hunt_triage(sid); hunt_poc(sid)
        validate_all(sid); autopilot(sid); build_report(sid); ok("resumed")
    elif a.cmd == "alert-test":
        banner(); send_alert("STRIX test alert", "INFO"); ok("alert dispatched")

if __name__ == "__main__":
    main()
