#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sitecheck — 외주로 만든 사이트의 PHP·Node.js 보안 점검.

  바깥 점검   python3 sitecheck.py https://example.com
  서버 점검   python3 sitecheck.py --server [사이트 폴더 ...]

본인이 운영하거나 관리를 맡은 사이트에만 쓴다.
표준 라이브러리만 쓴다 (Python 3.6 이상). 서버에 아무것도 설치하지 않고 파일 하나로 돈다.
서버 점검은 읽기만 한다 — 설정을 바꾸거나 프로그램을 다시 시작하지 않는다.
"""

import argparse
import datetime
import glob
import html
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

VERSION = "0.1.3"
UA = "sitecheck/" + VERSION
HOME = "https://github.com/joveyoon/sitecheck"
CREDIT = "sitecheck 로 점검했습니다 · " + HOME
TODAY = datetime.date.today()

DANGER, WARN, UNKNOWN, OK = "위험", "주의", "확인 못 함", "문제없음"
ORDER = {DANGER: 0, WARN: 1, UNKNOWN: 2, OK: 3}


# ─── 결과 ────────────────────────────────────────────────────────────

class Finding(object):
    """점검 결과 한 건.

    plain  사이트 주인이 읽는 쉬운 설명 (한 줄에 한 문장)
    ask    외주 업체에 보낼 요청 한 문장
    detail 개발자가 확인할 근거 (버전·경로·CVE)
    """

    def __init__(self, level, title, plain, ask=None, detail=None):
        self.level = level
        self.title = title
        self.plain = [plain] if isinstance(plain, str) else list(plain)
        self.ask = ask
        self.detail = list(detail or [])


class Report(object):
    def __init__(self, kind, target):
        self.kind = kind
        self.target = target
        self.when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        self.findings = []
        self.notes = []

    def add(self, f):
        if f is None:
            return
        if isinstance(f, list):
            self.findings.extend(x for x in f if x)
        else:
            self.findings.append(f)

    def sorted(self):
        return sorted(self.findings, key=lambda f: ORDER[f.level])

    def count(self, level):
        return sum(1 for f in self.findings if f.level == level)

    def headline(self):
        if self.count(DANGER):
            return "바로 고쳐야 할 문제가 %d개 있습니다." % self.count(DANGER)
        if self.count(WARN):
            return "급하진 않지만 고치면 좋은 것이 %d개 있습니다." % self.count(WARN)
        return "알려진 문제가 없습니다."

    def counts(self):
        return " · ".join("%s %d" % (lv, self.count(lv)) for lv in (DANGER, WARN, UNKNOWN, OK))


def progress(msg):
    sys.stderr.write("· %s\n" % msg)
    sys.stderr.flush()


# ─── 공통 도구 ───────────────────────────────────────────────────────

def run(cmd, timeout=30):
    """명령을 돌려 (종료 코드, 표준 출력). 실행 못 하면 (None, "")."""
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return None, ""
    return p.returncode, p.stdout.decode("utf-8", "replace")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, follow=True, limit=65536, timeout=15, data=None, headers=None, insecure=False):
    """(상태 코드, 헤더, 본문, 최종 주소). 접속 실패면 상태가 None 이고 본문에 사유가 들어 있다."""
    h = {"User-Agent": UA, "Accept": "*/*"}
    h.update(headers or {})
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=data, headers=h)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.getcode(), r.headers, r.read(limit), r.geturl()
    except urllib.error.HTTPError as e:
        try:
            body = e.read(limit)
        except Exception:
            body = b""
        return e.code, e.headers, body, url
    except Exception as e:
        return None, {}, str(e).encode("utf-8", "replace"), url


_cache = {}


def get_json(url, data=None):
    """JSON 을 받아 온다. 실패하면 None. 같은 요청은 한 번만 보낸다."""
    key = (url, data)
    if key not in _cache:
        hdr = {"Content-Type": "application/json"} if data else None
        st, _, body, _ = fetch(url, limit=32 * 1024 * 1024, timeout=30, data=data, headers=hdr)
        val = None
        if st == 200:
            try:
                val = json.loads(body.decode("utf-8"))
            except ValueError:
                pass
        _cache[key] = val
    return _cache[key]


def header_all(hd, name):
    get_all = getattr(hd, "get_all", None)
    return (get_all(name) or []) if get_all else []


def vtuple(s):
    m = re.match(r"v?(\d+(?:\.\d+)*)", str(s).strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else ()


def parse_date(s):
    try:
        y, m, d = (int(x) for x in str(s)[:10].split("-"))
        return datetime.date(y, m, d)
    except (ValueError, TypeError):
        return None


def passed(v):
    """endoflife.date 의 eol 값(날짜 또는 참거짓)이 이미 지났는가. eol: true 는 이미 끝났다는 뜻."""
    if isinstance(v, bool):
        return v
    d = parse_date(v)
    return d is not None and d <= TODAY


def support_ended(v):
    """endoflife.date 의 support 값. eol 과 반대로 support: true 는 아직 지원 중이라는 뜻."""
    if isinstance(v, bool):
        return not v
    return passed(v)


def read_text(path, limit=1024 * 1024):
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def which(name):
    return shutil.which(name)


# ─── 버전 판정 ───────────────────────────────────────────────────────

def eol_data(product):
    return get_json("https://endoflife.date/api/%s.json" % product)


def node_security_after(version):
    """installed 보다 새로 나온 같은 메이저의 보안 릴리스. 조회 실패면 None."""
    idx = get_json("https://nodejs.org/dist/index.json")
    if idx is None:
        return None
    v = vtuple(version)
    newer = [r["version"].lstrip("v") for r in idx
             if r.get("security") and vtuple(r["version"])[:1] == v[:1] and vtuple(r["version"]) > v]
    return sorted(newer, key=vtuple)


def judge_runtime(label, product, version, cycle_len, where, distro=None):
    """프로그램 버전 하나를 판정한다.

    distro 가 있으면 운영체제 패키지로 깐 것이다. 운영체제 회사가 보안 패치를 번호를 올리지 않고
    넣어 주므로, 같은 계열 최신 번호와 비교하지 않는다 (밀린 업데이트는 따로 본다).
    """
    det = ["%s %s — %s" % (label, version, where)]
    if distro:
        det.append("설치 출처: " + distro)
    data = eol_data(product)
    if data is None:
        return Finding(UNKNOWN, "%s %s — 최신 버전과 비교하지 못했습니다" % (label, version),
                       "최신 버전 정보를 인터넷에서 가져오지 못했습니다.", detail=det)
    cyc = ".".join(str(x) for x in vtuple(version)[:cycle_len])
    c = next((x for x in data if str(x.get("cycle")) == cyc), None)
    if c is None:
        return Finding(UNKNOWN, "%s %s — 처음 보는 버전입니다" % (label, version),
                       "버전 정보 목록에 없는 번호라 판단하지 못했습니다.", detail=det)
    latest = str(c.get("latest") or "")
    if latest:
        det.append("같은 계열 최신 버전: " + latest)

    if passed(c.get("eol")):
        alive = [x for x in data if not passed(x.get("eol"))]
        floor = str(alive[-1]["cycle"]) if alive else ""
        det.append("%s 계열 지원 종료일: %s" % (cyc, c.get("eol")))
        plain = ["%s %s 계열은 지원이 끝났습니다." % (label, cyc),
                 "보안 문제가 새로 나와도 더는 고쳐 주지 않습니다."]
        if distro:
            plain.append("운영체제 회사가 따로 고쳐 주는 경우도 있어서 확실하지는 않습니다.")
        ask = "%s 버전을 지원 중인 %s 이상으로 올려 주십시오." % (label, floor) if floor else None
        return Finding(WARN if distro else DANGER, "%s %s — 지원이 끝난 버전입니다" % (label, version),
                       plain, ask, det)

    if distro:
        return Finding(OK, "%s %s — 운영체제가 관리하는 버전입니다" % (label, version),
                       ["번호가 낮아 보여도 운영체제 회사가 보안 패치를 따로 넣어 줍니다.",
                        "밀린 업데이트는 '서버 업데이트' 항목에서 따로 봅니다."], detail=det)

    if latest and vtuple(version) < vtuple(latest):
        ask = "%s 버전을 %s 로 올려 주십시오." % (label, latest)
        if product == "nodejs":
            sec = node_security_after(version)
            if sec:
                det.append("이 버전 뒤에 나온 보안 릴리스: " + ", ".join(sec[:5]))
                return Finding(DANGER, "%s %s — 보안 패치가 나온 버전입니다" % (label, version),
                               ["이 버전 뒤에 보안 문제를 고친 새 버전이 나왔습니다.",
                                "지금 버전에는 그 문제가 그대로 남아 있습니다."], ask, det)
        elif c.get("support") is not None and support_ended(c.get("support")):
            return Finding(DANGER, "%s %s — 보안 패치가 나온 버전입니다" % (label, version),
                           ["%s 계열은 지금 보안 수정만 나오는 시기입니다." % cyc,
                            "그래서 이 뒤에 나온 패치는 모두 보안 문제를 고친 것입니다."], ask, det)
        return Finding(WARN, "%s %s — 최신 패치가 아닙니다" % (label, version),
                       ["같은 계열에 더 새로운 패치가 나와 있습니다.",
                        "보안 수정이 들어 있을 수 있습니다."], ask, det)

    return Finding(OK, "%s %s — 최신 패치입니다" % (label, version),
                   "지원 기간 안에 있고, 같은 계열의 최신 버전입니다.", detail=det)


# ─── 부품(라이브러리) 취약점 — OSV ──────────────────────────────────────

SEV_RANK = {"MALWARE": -1, "CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, None: 4}
SEV_KO = {"MALWARE": "악성 코드", "CRITICAL": "심각", "HIGH": "높음", "MODERATE": "보통",
          "MEDIUM": "보통", "LOW": "낮음", None: "등급 없음"}


def parse_package_lock(data):
    out = {}

    def put(name, ver, dev):
        if name and vtuple(ver) and "use.local" not in ver:
            out[(name, ver)] = out.get((name, ver), True) and dev

    pk = data.get("packages")
    if isinstance(pk, dict):
        for path, info in pk.items():
            if "node_modules/" not in path or info.get("link"):
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[1]
            put(name, str(info.get("version", "")), bool(info.get("dev") or info.get("devOptional")))
    else:
        def walk(deps):
            for name, info in (deps or {}).items():
                put(name, str(info.get("version", "")), bool(info.get("dev")))
                walk(info.get("dependencies"))
        walk(data.get("dependencies"))
    return [(n, v, d) for (n, v), d in out.items()]


def parse_yarn_lock(text):
    out, name = set(), None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
            spec = line.rstrip()[:-1].split(",")[0].strip().strip('"')
            at = spec.rfind("@")
            name = spec[:at] if at > 0 and not spec.startswith("__metadata") else None
        elif name:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
            if m:
                if vtuple(m.group(1)) and "use.local" not in m.group(1):
                    out.add((name, m.group(1), False))
                name = None
    return list(out)


def parse_pnpm_lock(text):
    out, cur, in_pk = {}, None, False
    for line in text.splitlines():
        if re.match(r"^\S", line):
            in_pk = line.startswith(("packages:", "snapshots:"))
            cur = None
            continue
        if not in_pk:
            continue
        m = re.match(r"^  '?/?((?:@[^@/\s']+/)?[^@/\s']+)@(\d[^(:'\s]*)", line)
        if m:
            cur = (m.group(1), m.group(2))
            out.setdefault(cur, False)
        elif cur and re.match(r"^\s+dev: true", line):
            out[cur] = True
    return [(n, v, d) for (n, v), d in out.items()]


def parse_composer_lock(data):
    out = []
    for key, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(key) or []:
            v = str(p.get("version", "")).lstrip("v")
            if p.get("name") and vtuple(v):
                out.append((p["name"], v, dev))
    return out


def parse_lockfile(name, raw):
    """잠금 파일 → (생태계, [(이름, 버전, 개발용)]). 못 읽으면 (None, [])."""
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    try:
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            return "npm", parse_package_lock(json.loads(text))
        if name == "composer.lock":
            return "Packagist", parse_composer_lock(json.loads(text))
    except (ValueError, AttributeError):
        return None, []
    if name == "yarn.lock":
        return "npm", parse_yarn_lock(text)
    if name == "pnpm-lock.yaml":
        return "npm", parse_pnpm_lock(text)
    return None, []


def osv_scan(pkgs, ecosystem):
    """[(이름, 버전, 개발용, [취약점 id])]. 조회 실패면 None."""
    hits = []
    for i in range(0, len(pkgs), 500):
        chunk = pkgs[i:i + 500]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": ecosystem}, "version": v}
                                       for n, v, _ in chunk]}).encode()
        data = get_json("https://api.osv.dev/v1/querybatch", body)
        if data is None:
            return None
        for (n, v, dev), r in zip(chunk, data.get("results", [])):
            ids = [x["id"] for x in (r.get("vulns") or [])]
            if ids:
                hits.append((n, v, dev, ids))
    return hits


def vuln_severity(v):
    if v.get("id", "").startswith("MAL-"):
        return "MALWARE"
    s = (v.get("database_specific") or {}).get("severity")
    return s.upper() if isinstance(s, str) and s.upper() in SEV_RANK else None


def fixed_version(v, name, current):
    cands = []
    for a in v.get("affected") or []:
        if (a.get("package") or {}).get("name") != name:
            continue
        for r in a.get("ranges") or []:
            for e in r.get("events") or []:
                if "fixed" in e and vtuple(e["fixed"]) > vtuple(current):
                    cands.append(e["fixed"])
    return min(cands, key=vtuple) if cands else None


def deps_finding(where, lockname, ecosystem, pkgs):
    tool = "composer update" if ecosystem == "Packagist" else "npm audit fix 등"
    hits = osv_scan(pkgs, ecosystem)
    det = ["%s (%s, 부품 %d개)" % (where, lockname, len(pkgs))]
    if hits is None:
        return Finding(UNKNOWN, "사이트 부품의 보안 문제를 조회하지 못했습니다",
                       "취약점 정보(OSV)를 인터넷에서 가져오지 못했습니다.", detail=det)
    if not hits:
        return Finding(OK, "사이트 부품 %d개 — 알려진 보안 문제가 없습니다" % len(pkgs),
                       "사이트를 만들 때 가져다 쓴 부품(라이브러리)을 모두 확인했습니다.", detail=det)

    ids = sorted({i for h in hits for i in h[3]})[:300]
    with ThreadPoolExecutor(8) as ex:
        infos = dict(zip(ids, ex.map(lambda i: get_json("https://api.osv.dev/v1/vulns/" + i), ids)))

    rows = []
    for name, ver, dev, vids in hits:
        vs = [infos.get(i) or {"id": i} for i in vids]
        sev = min((vuln_severity(v) for v in vs), key=lambda s: SEV_RANK[s])
        cves = sorted({a for v in vs for a in (v.get("aliases") or []) if a.startswith("CVE-")})
        fixes = [f for f in (fixed_version(v, name, ver) for v in vs) if f]
        fix = max(fixes, key=vtuple) if fixes else None
        rows.append((SEV_RANK[sev], name, ver, dev, sev, cves or vids, fix))
    rows.sort()

    severe = [r for r in rows if r[0] <= 1 and not r[3]]
    plain = ["사이트를 만들 때 가져다 쓴 부품(라이브러리) %d개 중 %d개에 알려진 보안 문제가 있습니다."
             % (len(pkgs), len(rows))]
    if severe:
        plain.append("그중 %d개는 심각도가 높습니다." % len(severe))
    elif all(r[3] for r in rows):
        plain.append("모두 개발할 때만 쓰는 부품이라 실제 사이트에 주는 영향은 작습니다.")
    for _, name, ver, dev, sev, refs, fix in rows[:20]:
        det.append("%s %s · %s%s · %s%s" % (
            name, ver, SEV_KO[sev], " · 개발용" if dev else "", ", ".join(refs[:3]),
            " · %s 에서 고쳐짐" % fix if fix else ""))
    if len(rows) > 20:
        det.append("외 %d개" % (len(rows) - 20))
    return Finding(DANGER if severe else WARN,
                   "사이트 부품 %d개에 알려진 보안 문제가 있습니다" % len(rows), plain,
                   "%s 의 부품을 보안 문제가 고쳐진 버전으로 올려 주십시오 (%s)." % (where, tool), det)


# ─── 바깥 점검 ───────────────────────────────────────────────────────

def tls_info(host, port):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert, proto = t.getpeercert(), t.version()
        exp = ssl.cert_time_to_seconds(cert["notAfter"])
        return {"ok": True, "days": int((exp - time.time()) // 86400), "proto": proto,
                "until": time.strftime("%Y-%m-%d", time.localtime(exp))}
    except ssl.SSLError as e:
        return {"ok": False, "error": str(e)}
    except OSError as e:
        return {"ok": None, "error": str(e)}


def tls_finding(tls, scheme):
    if tls["ok"] is None:
        if scheme == "http":
            return Finding(DANGER, "암호화 연결(https)이 없습니다",
                           ["방문자가 입력하는 내용이 암호화되지 않고 오갑니다.",
                            "브라우저 주소창에 '주의 요함'이 뜹니다."],
                           "보안 인증서(SSL)를 설치해 https 로 접속되게 해 주십시오.", [tls["error"]])
        return Finding(UNKNOWN, "보안 인증서를 확인하지 못했습니다", "443 포트에 접속하지 못했습니다.",
                       detail=[tls["error"]])
    if tls["ok"] is False:
        return Finding(DANGER, "보안 인증서에 문제가 있습니다",
                       ["방문자 브라우저에 '안전하지 않음' 경고가 뜹니다.",
                        "만료됐거나 다른 주소용 인증서일 수 있습니다."],
                       "보안 인증서(SSL)를 올바르게 다시 설치해 주십시오.", [tls["error"]])
    det = ["만료일 %s (%d일 남음) · %s" % (tls["until"], tls["days"], tls["proto"])]
    if tls["days"] <= 7:
        return Finding(DANGER, "보안 인증서가 %d일 뒤 만료됩니다" % tls["days"],
                       ["만료되면 방문자 브라우저에 경고가 뜨고 사이트에 들어오기 어렵습니다.",
                        "자동 갱신이 멈춘 것 같습니다."],
                       "보안 인증서를 갱신하고 자동 갱신이 되는지 확인해 주십시오.", det)
    if tls["days"] <= 20:
        return Finding(WARN, "보안 인증서가 %d일 뒤 만료됩니다" % tls["days"],
                       ["보통은 만료 30일 전에 자동으로 갱신됩니다.",
                        "아직 갱신되지 않아서 자동 갱신이 멈췄을 수 있습니다."],
                       "보안 인증서 자동 갱신이 되는지 확인해 주십시오.", det)
    return Finding(OK, "보안 인증서가 정상입니다", "https 연결과 인증서에 문제가 없습니다.", detail=det)


def http_redirect_finding(netloc):
    st, hd, _, _ = fetch("http://%s/" % netloc, follow=False, timeout=8)
    if st is None:
        return None
    loc = hd.get("Location", "") if hd else ""
    if st in (301, 302, 303, 307, 308) and loc.startswith("https://"):
        return Finding(OK, "http 로 들어와도 https 로 넘겨 줍니다",
                       "주소를 http 로 쳐도 암호화된 화면으로 바로 넘어갑니다.")
    return Finding(WARN, "http 로 들어오면 암호화 없이 열립니다",
                   ["주소를 http 로 치고 들어온 방문자는 암호화되지 않은 화면을 봅니다.",
                    "같은 와이파이에 있는 사람이 입력 내용을 엿볼 수 있습니다."],
                   "http 접속을 https 로 자동으로 넘겨 주십시오.",
                   ["http://%s/ → %s" % (netloc, st)])


def header_findings(hd, final_url):
    out = []
    server = hd.get("Server") if hd else None
    xpb = header_all(hd, "X-Powered-By")
    shown = (["Server: " + server] if server else []) + ["X-Powered-By: " + x for x in xpb]
    versioned = [s for s in shown if re.search(r"/\d", s)]
    if versioned:
        out.append(Finding(WARN, "사이트가 쓰는 프로그램 버전이 밖에서 보입니다",
                           ["응답에 서버 프로그램 이름과 버전 번호가 적혀 나갑니다.",
                            "공격자가 그 버전의 약점을 골라 노릴 수 있습니다."],
                           "응답 헤더에서 버전 번호를 숨겨 주십시오 "
                           "(nginx: server_tokens off, PHP: expose_php = Off).", versioned))
    for x in xpb:
        m = re.match(r"PHP/(\d+\.\d+\.\d+)(\S*)", x)
        if m:
            suffix = m.group(2).lstrip("-+")
            out.append(judge_runtime("PHP", "php", m.group(1), 2, "응답 헤더 X-Powered-By",
                                     distro=("운영체제 패키지 " + suffix) if suffix else None))

    missing = []
    if final_url.startswith("https://") and not hd.get("Strict-Transport-Security"):
        missing.append("Strict-Transport-Security — 늘 암호화 연결로만 접속하게 합니다")
    if (hd.get("X-Content-Type-Options") or "").lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff — 파일 종류를 속이는 공격을 막습니다")
    if not hd.get("X-Frame-Options") and "frame-ancestors" not in (hd.get("Content-Security-Policy") or ""):
        missing.append("X-Frame-Options 또는 CSP frame-ancestors — 다른 사이트가 몰래 겹쳐 띄우는 것을 막습니다")
    if missing:
        out.append(Finding(WARN, "브라우저 보호 설정 %d개가 빠져 있습니다" % len(missing),
                           ["사이트가 브라우저에 알려 주는 보호 설정이 빠져 있습니다.",
                            "당장 뚫리는 문제는 아니지만, 흔한 공격을 한 겹 더 막아 줍니다."],
                           "보안 응답 헤더를 추가해 주십시오.", missing))
    else:
        out.append(Finding(OK, "브라우저 보호 설정이 들어가 있습니다", "기본 보안 응답 헤더가 모두 있습니다."))
    return out


def _not_html(b):
    return b"<html" not in b[:4096].lower() and b"<!doctype" not in b[:4096].lower()


def _json_has(*keys):
    def check(b):
        try:
            d = json.loads(b.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        return isinstance(d, dict) and any(k in d for k in keys)
    return check


EXPOSED = [
    ("/.env", "env", lambda b: _not_html(b) and len(re.findall(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", b)) >= 2),
    ("/.env.production", "env", lambda b: _not_html(b) and len(re.findall(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", b)) >= 2),
    ("/.env.local", "env", lambda b: _not_html(b) and len(re.findall(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", b)) >= 2),
    ("/.git/HEAD", "git", lambda b: b.startswith(b"ref: refs/") or re.match(rb"^[0-9a-f]{40}\s*$", b) is not None),
    ("/.git/config", "git", lambda b: _not_html(b) and b"[core]" in b),
    ("/wp-config.php.bak", "wpbak", lambda b: b"DB_PASSWORD" in b),
    ("/wp-config.php~", "wpbak", lambda b: b"DB_PASSWORD" in b),
    ("/wp-config.php.save", "wpbak", lambda b: b"DB_PASSWORD" in b),
    ("/wp-config.php.old", "wpbak", lambda b: b"DB_PASSWORD" in b),
    ("/wp-config.bak", "wpbak", lambda b: b"DB_PASSWORD" in b),
    ("/backup.sql", "sql", lambda b: _not_html(b) and re.search(rb"CREATE TABLE|INSERT INTO", b[:8192]) is not None),
    ("/dump.sql", "sql", lambda b: _not_html(b) and re.search(rb"CREATE TABLE|INSERT INTO", b[:8192]) is not None),
    ("/db.sql", "sql", lambda b: _not_html(b) and re.search(rb"CREATE TABLE|INSERT INTO", b[:8192]) is not None),
    ("/backup.zip", "archive", lambda b: b.startswith(b"PK\x03\x04")),
    ("/www.zip", "archive", lambda b: b.startswith(b"PK\x03\x04")),
    ("/site.zip", "archive", lambda b: b.startswith(b"PK\x03\x04")),
    ("/backup.tar.gz", "archive", lambda b: b.startswith(b"\x1f\x8b")),
    ("/phpinfo.php", "phpinfo", lambda b: re.search(rb"phpinfo\(\)|PHP Version \d", b) is not None),
    ("/info.php", "phpinfo", lambda b: re.search(rb"phpinfo\(\)|PHP Version \d", b) is not None),
    ("/test.php", "phpinfo", lambda b: re.search(rb"phpinfo\(\)|PHP Version \d", b) is not None),
    ("/composer.lock", "lock", _json_has("packages")),
    ("/package-lock.json", "lock", _json_has("lockfileVersion")),
    ("/composer.json", "manifest", _json_has("require")),
    ("/package.json", "manifest", _json_has("dependencies", "devDependencies")),
    ("/server-status", "status", lambda b: b"Apache Server Status" in b),
    ("/nginx_status", "status", lambda b: b"Active connections:" in b),
    ("/.DS_Store", "dsstore", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1")),
    ("/wp-content/uploads/", "listing", lambda b: re.search(rb"<title>Index of /", b) is not None),
    ("/uploads/", "listing", lambda b: re.search(rb"<title>Index of /", b) is not None),
]

EXPOSED_INFO = {
    "env": (DANGER, "비밀 설정 파일(.env)이 밖에서 열립니다",
            ["데이터베이스 비밀번호·API 키가 흔히 들어 있는 파일입니다.", "지금 누구나 내려받을 수 있습니다."],
            "이 파일이 밖에서 열리지 않게 막아 주십시오. 안에 있던 비밀번호와 키는 이미 샜다고 보고 모두 새로 바꿔 주십시오."),
    "git": (DANGER, "소스 코드 저장소(.git)가 밖에서 열립니다",
            ["사이트 소스 코드 전체를 내려받을 수 있는 상태입니다.", "코드에 적힌 비밀번호까지 함께 샐 수 있습니다."],
            "웹 서버에서 .git 폴더 접근을 막아 주십시오. 코드에 있던 비밀번호와 키는 새로 바꿔 주십시오."),
    "wpbak": (DANGER, "워드프레스 설정 백업 파일이 밖에서 열립니다",
              ["데이터베이스 비밀번호가 그대로 적힌 파일입니다.", "지금 누구나 내려받을 수 있습니다."],
              "백업 파일을 지우고 데이터베이스 비밀번호를 새로 바꿔 주십시오."),
    "sql": (DANGER, "데이터베이스 백업 파일이 밖에서 열립니다",
            ["회원 정보 같은 사이트 데이터가 통째로 들어 있을 수 있습니다.", "지금 누구나 내려받을 수 있습니다."],
            "백업 파일을 웹에서 열리지 않는 곳으로 옮기거나 지워 주십시오."),
    "archive": (DANGER, "사이트 백업 압축 파일이 밖에서 열립니다",
                ["소스 코드와 설정 파일이 통째로 들어 있을 수 있습니다.", "지금 누구나 내려받을 수 있습니다."],
                "압축 파일을 웹에서 열리지 않는 곳으로 옮기거나 지워 주십시오."),
    "phpinfo": (WARN, "서버 설정 정보 페이지가 열려 있습니다",
                ["PHP 버전과 서버 설정이 자세히 보입니다.", "공격자가 약점을 찾을 때 쓰는 정보입니다."],
                "phpinfo 페이지 파일을 지워 주십시오."),
    "lock": (WARN, "사이트 부품 목록이 밖에서 보입니다",
             ["어떤 부품(라이브러리)을 어떤 버전으로 쓰는지 누구나 알 수 있습니다."],
             "부품 목록 파일이 밖에서 열리지 않게 막아 주십시오."),
    "manifest": (WARN, "사이트 설정 파일이 밖에서 보입니다",
                 ["사이트를 만든 방식과 쓰는 부품 이름이 드러납니다."],
                 "composer.json·package.json 이 밖에서 열리지 않게 막아 주십시오."),
    "status": (WARN, "서버 상태 페이지가 열려 있습니다",
               ["접속 중인 주소와 서버 상태가 누구에게나 보입니다."],
               "서버 상태 페이지는 서버 안에서만 열리게 막아 주십시오."),
    "dsstore": (WARN, "폴더 목록 파일(.DS_Store)이 올라가 있습니다",
                ["서버 폴더 안의 파일 이름이 드러납니다."], ".DS_Store 파일을 지워 주십시오."),
    "listing": (WARN, "폴더 안 파일 목록이 그대로 보입니다",
                ["올린 파일 이름이 모두 보여서 숨겨야 할 파일도 찾기 쉽습니다."],
                "웹 서버에서 폴더 목록 보기를 꺼 주십시오."),
}


def exposed_findings(base, insecure):
    def probe(item):
        path, kind, check = item
        limit = 16 * 1024 * 1024 if kind == "lock" else 65536
        st, _, body, _ = fetch(base + path, follow=False, limit=limit, timeout=10, insecure=insecure)
        return (path, kind, body) if st == 200 and check(body) else None

    with ThreadPoolExecutor(6) as ex:
        hits = [h for h in ex.map(probe, EXPOSED) if h]

    out = []
    for kind in EXPOSED_INFO:
        paths = [base + p for p, k, _ in hits if k == kind]
        if paths:
            level, title, plain, ask = EXPOSED_INFO[kind]
            out.append(Finding(level, title, plain, ask, paths))
    for path, kind, body in hits:
        if kind == "lock":
            eco, pkgs = parse_lockfile(path.lstrip("/"), body)
            if pkgs:
                out.append(deps_finding(base + path, path.lstrip("/"), eco, pkgs))
    if not hits:
        out.append(Finding(OK, "밖에서 열리면 안 되는 파일이 열리지 않습니다",
                           "비밀 설정·백업·소스 저장소처럼 자주 새는 파일 %d곳을 확인했습니다." % len(EXPOSED)))
    return out


def wordpress_remote(base, body, insecure):
    out = []
    m = re.search(rb'<meta name="generator" content="WordPress ([\d.]+)"', body)
    if not m:
        _, _, feed, _ = fetch(base + "/feed/", timeout=10, insecure=insecure)
        m = re.search(rb"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>", feed)
    if m:
        out.append(judge_runtime("워드프레스", "wordpress", m.group(1).decode(), 2, "사이트 화면의 버전 표시"))
    else:
        out.append(Finding(UNKNOWN, "워드프레스 버전을 밖에서 알 수 없습니다",
                           ["버전 표시를 숨겨 둔 상태입니다.", "숨긴 것 자체는 좋습니다."],
                           detail=["서버 점검(--server)으로 확인할 수 있습니다."]))

    for path in ("/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users"):
        st, _, b, _ = fetch(base + path, timeout=10, insecure=insecure)
        try:
            users = json.loads(b.decode("utf-8")) if st == 200 else None
        except (ValueError, UnicodeDecodeError):
            users = None
        if isinstance(users, list) and users and isinstance(users[0], dict) and "slug" in users[0]:
            out.append(Finding(WARN, "관리자 로그인 아이디가 밖에서 보입니다",
                               ["워드프레스가 글쓴이 목록을 누구에게나 보여 줍니다.",
                                "그 이름이 로그인 아이디와 같아서 비밀번호만 맞히면 들어갈 수 있습니다."],
                               "REST API 의 사용자 목록(/wp-json/wp/v2/users)을 로그인한 사람만 보게 막아 주십시오.",
                               [base + path, "보이는 아이디: " + ", ".join(u.get("slug", "") for u in users[:5])]))
            break

    st, _, b, _ = fetch(base + "/xmlrpc.php", timeout=10, insecure=insecure)
    if st in (200, 405) and b"XML-RPC server accepts POST requests only" in b:
        out.append(Finding(WARN, "비밀번호를 마구 대입해 보는 통로(xmlrpc.php)가 열려 있습니다",
                           ["예전 방식의 원격 글쓰기 통로입니다.",
                            "한 번에 수백 개의 비밀번호를 시험해 볼 수 있어서 자주 공격받습니다."],
                           "xmlrpc.php 를 쓰지 않으면 접근을 막아 주십시오.", [base + "/xmlrpc.php"]))
    return out


def remote_check(url):
    if "://" not in url:
        url = "https://" + url
    u = urllib.parse.urlsplit(url)
    if not u.hostname:
        raise SystemExit("주소를 알아보지 못했습니다: " + url)
    base = "%s://%s" % (u.scheme, u.netloc)
    rep = Report("바깥 점검", base)
    rep.notes.append("사이트 바깥에서 누구나 볼 수 있는 것만 봤습니다.")
    rep.notes.append("서버 안의 PHP·Node.js 버전과 부품은 서버 점검(--server)으로 확인합니다.")

    progress("보안 인증서 확인")
    port = 443 if u.scheme == "http" else (u.port or 443)
    tls = tls_info(u.hostname, port)
    rep.add(tls_finding(tls, u.scheme))
    insecure = tls["ok"] is False

    progress("첫 화면 확인")
    st, hd, body, final = fetch(base + "/", limit=2 * 1024 * 1024, insecure=insecure)
    if st is None:
        rep.add(Finding(UNKNOWN, "사이트에 접속하지 못했습니다",
                        "주소가 맞는지, 사이트가 열려 있는지 확인해 주십시오.",
                        detail=[body.decode("utf-8", "replace")[:200]]))
        return rep

    progress("http 접속 확인")
    rep.add(http_redirect_finding(u.hostname))
    rep.add(header_findings(hd, final))

    progress("밖에서 열리면 안 되는 파일 확인")
    rep.add(exposed_findings(base, insecure))

    if b"/wp-content/" in body or b"/wp-includes/" in body:
        progress("워드프레스 확인")
        rep.add(wordpress_remote(base, body, insecure))
        rep.notes.append("워드프레스 플러그인은 서버 점검(--server)에서 확인합니다.")
    if b"/_next/static" in body or "Next.js" in " ".join(header_all(hd, "X-Powered-By")):
        rep.notes.append("Next.js 로 만든 사이트입니다. Next.js 는 최근 심각한 보안 문제가 여러 번 나왔습니다. "
                         "버전은 서버 점검(--server)으로 확인합니다.")
    return rep


# ─── 서버 점검 ───────────────────────────────────────────────────────

OS_PRODUCTS = {"ubuntu": "ubuntu", "debian": "debian", "rocky": "rocky-linux", "almalinux": "almalinux",
               "centos": "centos", "rhel": "rhel", "amzn": "amazon-linux", "ol": "oracle-linux"}


def os_finding():
    info = dict(re.findall(r'(?m)^(\w+)="?([^"\n]*)"?', read_text("/etc/os-release")))
    name, vid = info.get("PRETTY_NAME", "알 수 없는 운영체제"), info.get("VERSION_ID", "")
    prod = OS_PRODUCTS.get(info.get("ID"))
    if not prod:
        return Finding(UNKNOWN, "서버 운영체제(%s) 지원 기간을 확인하지 못했습니다" % name,
                       "지원 기간 정보가 없는 운영체제입니다.")
    data = eol_data(prod)
    c = next((x for x in data or [] if str(x.get("cycle")) in (vid, vid.split(".")[0])), None)
    if c is None:
        return Finding(UNKNOWN, "서버 운영체제(%s) 지원 기간을 확인하지 못했습니다" % name,
                       "지원 기간 정보를 가져오지 못했습니다.")
    det = ["%s · 지원 종료 %s" % (name, c.get("eol"))]
    if passed(c.get("eol")):
        plain = ["서버 운영체제가 더는 보안 패치를 받지 못합니다.",
                 "그 위에서 도는 PHP·Node.js 를 최신으로 해도 서버 자체가 약합니다."]
        if c.get("extendedSupport") and not passed(c.get("extendedSupport")):
            plain.append("유료 연장 지원(예: Ubuntu Pro)에 가입했다면 패치가 계속 나옵니다.")
        return Finding(DANGER, "서버 운영체제 지원이 끝났습니다", plain,
                       "서버 운영체제를 지원 중인 버전으로 올려 주십시오.", det)
    return Finding(OK, "서버 운영체제가 지원 기간 안에 있습니다",
                   "%s 은 %s 까지 보안 패치를 받습니다." % (name, c.get("eol")), detail=det)


def updates_finding():
    if which("apt"):
        rc, out = run(["apt", "list", "--upgradable"], 60)
        if rc != 0:
            return Finding(UNKNOWN, "밀린 서버 업데이트를 확인하지 못했습니다", "업데이트 목록을 읽지 못했습니다.")
        sec, other = [], []
        for line in out.splitlines():
            m = re.match(r"^(\S+?)/(\S+)\s+(\S+)", line)
            if m:
                (sec if "security" in m.group(2) else other).append("%s → %s" % (m.group(1), m.group(3)))
        lists = glob.glob("/var/lib/apt/lists/*Release")
        age = int((time.time() - max(os.path.getmtime(f) for f in lists)) // 86400) if lists else None
        tool = "sudo apt update && sudo apt upgrade"
    elif which("dnf") or which("yum"):
        pm = "dnf" if which("dnf") else "yum"
        rc, out = run([pm, "-q", "-C", "check-update"], 120)
        if rc not in (0, 100):
            return Finding(UNKNOWN, "밀린 서버 업데이트를 확인하지 못했습니다", "업데이트 목록을 읽지 못했습니다.")
        names = [l.split()[0] for l in out.splitlines() if re.match(r"^\S+\.\S+\s+\S+\s+\S+", l)]
        rc2, out2 = run([pm, "-q", "-C", "updateinfo", "list", "--security"], 120)
        secnames = {l.split()[-1] for l in out2.splitlines() if l.strip()} if rc2 == 0 else set()
        sec = [n for n in names if any(s.startswith(n.rsplit(".", 1)[0]) for s in secnames)]
        other = [n for n in names if n not in sec]
        age, tool = None, "sudo %s upgrade --security" % pm
    else:
        return None

    det = []
    if age is not None and age > 7:
        det.append("업데이트 목록을 %d일 전에 받아 와서 실제로는 더 있을 수 있습니다." % age)
    if sec:
        return Finding(DANGER, "설치 안 한 보안 업데이트가 %d개 있습니다" % len(sec),
                       ["운영체제 회사가 보안 문제를 고친 업데이트를 내놨는데 아직 설치하지 않았습니다."],
                       "서버 보안 업데이트를 설치하고(%s) 웹 서버·PHP·Node.js 를 다시 시작해 주십시오." % tool,
                       det + sec[:15] + (["외 %d개" % (len(sec) - 15)] if len(sec) > 15 else []))
    if other:
        return Finding(WARN, "설치 안 한 업데이트가 %d개 있습니다" % len(other),
                       ["보안 표시가 없는 일반 업데이트입니다.", "PHP 처럼 외부 저장소에서 받는 것은 보안 수정이어도 이렇게 보입니다."],
                       "서버 업데이트를 설치해 주십시오 (%s)." % tool,
                       det + other[:15] + (["외 %d개" % (len(other) - 15)] if len(other) > 15 else []))
    level = UNKNOWN if age is not None and age > 30 else OK
    return Finding(level, "밀린 서버 업데이트가 없습니다", "운영체제 업데이트가 모두 설치돼 있습니다.", detail=det)


def install_source(path):
    """(설명, 운영체제가 관리하는가). 패키지로 깐 게 아니면 (None, False)."""
    real = os.path.realpath(path)
    if which("dpkg-query"):
        rc, out = run(["dpkg-query", "-S", real])
        if rc == 0 and out:
            pkg = out.split(": ", 1)[0].split(",")[0].split(":")[0].strip()
            _, ver = run(["dpkg-query", "-W", "-f=${Version}", pkg])
            return "%s %s" % (pkg, ver.strip()), not re.search(r"sury|nodesource", ver)
    if which("rpm"):
        rc, out = run(["rpm", "-qf", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n", real])
        if rc == 0 and out.strip():
            line = out.strip().splitlines()[0]
            return line, not re.search(r"remi|nodesource", line)
    return None, False


PHP_GLOBS = ["/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/local/bin/php*", "/usr/local/sbin/php-fpm*",
             "/opt/remi/php*/root/usr/bin/php", "/opt/remi/php*/root/usr/sbin/php-fpm",
             "/opt/plesk/php/*/bin/php", "/opt/cpanel/ea-php*/root/usr/bin/php"]


def php_binaries():
    found = {}
    for g in PHP_GLOBS:
        for p in sorted(glob.glob(g)):
            if not re.match(r"^php(-fpm)?[\d.]*$", os.path.basename(p)):
                continue
            real = os.path.realpath(p)
            if real in found or not os.access(real, os.X_OK):
                continue
            _, out = run([real, "-v"])
            m = re.search(r"PHP (\d+\.\d+\.\d+)", out)
            if m:
                found[real] = m.group(1)
    return found


def runtime_findings(label, product, cycle_len, binaries):
    """같은 버전·같은 출처의 실행 파일을 묶어 판정한다."""
    groups = {}
    for path, ver in sorted(binaries.items()):
        src, managed = install_source(path)
        paths, srcs = groups.setdefault((ver, managed), ([], []))
        paths.append(path)
        if src and src not in srcs:
            srcs.append(src)
    return [judge_runtime(label, product, ver, cycle_len, ", ".join(paths),
                          distro=("운영체제 패키지 " + ", ".join(srcs)) if managed else None)
            for (ver, managed), (paths, srcs) in groups.items()]


def php_settings_findings(binaries):
    out, checked = [], []
    for path in sorted(binaries):
        if "fpm" not in os.path.basename(path):
            continue
        _, info = run([path, "-i"])
        vals = dict(re.findall(r"(?m)^(display_errors|expose_php|allow_url_include) => (.*?) => ", info))
        if not vals:
            continue
        checked.append(path)
        on = lambda k: vals.get(k, "").strip().lower() in ("on", "1", "stdout")
        det = ["%s · 사이트별 설정(풀 설정, .user.ini)은 따로 바뀌어 있을 수 있습니다." % path]
        if on("allow_url_include"):
            out.append(Finding(DANGER, "PHP 가 다른 서버의 코드를 불러와 실행할 수 있게 돼 있습니다",
                               ["허점이 하나만 있어도 공격자의 코드를 그대로 실행할 수 있는 설정입니다."],
                               "PHP 설정 allow_url_include 를 Off 로 바꿔 주십시오.", det))
        if on("display_errors"):
            out.append(Finding(WARN, "PHP 오류 내용이 방문자 화면에 보입니다",
                               ["오류가 나면 서버 폴더 위치나 코드 일부가 화면에 드러납니다."],
                               "운영 서버에서는 PHP 설정 display_errors 를 Off 로 바꿔 주십시오.", det))
        if on("expose_php"):
            out.append(Finding(WARN, "PHP 버전이 응답에 적혀 나갑니다",
                               ["공격자가 PHP 버전을 보고 맞는 약점을 고를 수 있습니다."],
                               "PHP 설정 expose_php 를 Off 로 바꿔 주십시오.", det))
    if checked and not out:
        out.append(Finding(OK, "PHP 위험 설정이 꺼져 있습니다",
                           "오류 노출·원격 코드 불러오기·버전 표시가 모두 꺼져 있습니다.", detail=checked))
    return out


def processes():
    """실행 중인 PHP-FPM 주 프로세스와 Node.js 프로세스."""
    _, out = run(["ps", "-eo", "pid=,lstart=,args="])
    procs = []
    for line in out.splitlines():
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        try:
            pid = int(parts[0])
            start = time.mktime(time.strptime(" ".join(parts[1:6]), "%a %b %d %H:%M:%S %Y"))
        except ValueError:
            continue
        args = parts[6]
        try:
            exe = os.readlink("/proc/%d/exe" % pid)
        except OSError:
            exe = None
        first = os.path.basename(args.split()[0]) if args.split() else ""
        if args.startswith("php-fpm: master process"):
            m = re.search(r"/etc/php/(\d+\.\d+)/fpm/", args)
            guess = "/usr/sbin/php-fpm" + (m.group(1) if m else "")
            name = "php%s-fpm" % (m.group(1) if m else "")
            procs.append(dict(kind="php", pid=pid, start=start, exe=exe, args=args,
                              guess=guess if os.path.exists(guess) else which("php-fpm"), name=name))
        elif (exe and os.path.basename(exe).split(" ")[0] in ("node", "nodejs")) or \
                (exe is None and (first in ("node", "nodejs") or args.startswith(("PM2 v", "next-server")))):
            guess = args.split()[0] if args.startswith("/") else which("node")
            procs.append(dict(kind="node", pid=pid, start=start, exe=exe, args=args, guess=guess,
                              name=args[:60]))
    return procs


def stale_finding(procs):
    if not procs:
        return None
    stale = []
    for p in procs:
        exe = p["exe"]
        if exe and exe.endswith(" (deleted)"):
            stale.append(p)
            continue
        try:
            changed = os.stat(exe or p["guess"]).st_ctime
        except (OSError, TypeError):
            continue
        if p["start"] < changed - 60:
            stale.append(p)
    if not stale:
        return Finding(OK, "실행 중인 PHP·Node.js 가 설치된 버전과 같습니다",
                       "업데이트한 뒤 다시 시작하지 않은 프로그램이 없습니다.",
                       detail=["확인한 프로세스 %d개" % len(procs)])
    det = []
    for p in stale:
        det.append("pid %d · %s · %s 에 시작" % (p["pid"], p["name"],
                                            time.strftime("%Y-%m-%d %H:%M", time.localtime(p["start"]))))
    cmds = sorted({"sudo systemctl reload %s" % p["name"] for p in stale if p["kind"] == "php"})
    if any(p["kind"] == "node" for p in stale):
        cmds.append("pm2 reload all (또는 서비스 재시작)")
    det.append("다시 시작 예: " + ", ".join(cmds))
    return Finding(DANGER, "업데이트한 뒤 다시 시작하지 않은 프로그램이 있습니다",
                   ["프로그램을 새 버전으로 바꿨지만, 실행 중인 것은 아직 옛 버전입니다.",
                    "다시 시작해야 보안 패치가 실제로 적용됩니다."],
                   "업데이트한 PHP·Node.js 를 다시 시작해 주십시오.", det)


def node_binaries(procs):
    cands = [which("node"), which("nodejs"), "/usr/bin/node", "/usr/local/bin/node"]
    cands += [p["exe"] for p in procs if p["kind"] == "node" and p["exe"] and "(deleted)" not in p["exe"]]
    found = {}
    for c in cands:
        if not c or not os.path.exists(c):
            continue
        real = os.path.realpath(c)
        if real in found:
            continue
        _, out = run([real, "-v"])
        if re.match(r"v\d+\.\d+\.\d+", out.strip()):
            found[real] = out.strip().lstrip("v")
    return found


def pm2_dirs():
    dirs = []
    for f in glob.glob("/home/*/.pm2/dump.pm2") + glob.glob("/root/.pm2/dump.pm2"):
        try:
            apps = json.loads(read_text(f, 16 * 1024 * 1024))
        except ValueError:
            continue
        for a in apps if isinstance(apps, list) else []:
            cwd = a.get("pm_cwd") or (a.get("pm2_env") or {}).get("pm_cwd")
            if cwd:
                dirs.append(cwd)
    return dirs


def web_roots():
    roots = []
    for pat in ("/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*",
                "/etc/apache2/sites-enabled/*", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf"):
        for f in glob.glob(pat):
            text = read_text(f)
            roots += re.findall(r"(?m)^\s*root\s+[\"']?([^;\"'\s]+)", text)
            roots += re.findall(r"(?mi)^\s*DocumentRoot\s+[\"']?([^\"'\s]+)", text)
    return [r for r in roots if "$" not in r]


LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock")
SKIP_DIRS = {"node_modules", "vendor", "bower_components", "uploads", "cache", "__pycache__",
             "venv", "site-packages", "snap", "proc", "sys"}


def find_projects(extra, procs):
    """잠금 파일과 워드프레스 폴더를 찾는다. (잠금 파일, 워드프레스, 읽지 못한 폴더 수)"""
    roots = list(extra) + web_roots() + pm2_dirs()
    for p in procs:
        try:
            roots.append(os.readlink("/proc/%d/cwd" % p["pid"]))
        except OSError:
            pass
    roots += ["/var/www", "/srv", "/opt"] + sorted(glob.glob("/home/*"))
    if os.geteuid() == 0:
        roots.append("/root")

    seen, locks, wps, denied = set(), [], [], [0]

    def onerror(e):
        denied[0] += 1

    for r in roots:
        r = os.path.realpath(r)
        if not os.path.isdir(r):
            continue
        base = r.rstrip("/").count("/")
        for dp, dns, fns in os.walk(r, onerror=onerror):
            if dp in seen or len(seen) > 50000:
                dns[:] = []
                continue
            seen.add(dp)
            if "wp-includes" in dns and os.path.exists(os.path.join(dp, "wp-includes", "version.php")):
                wps.append(dp)
            dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.startswith(".")]
            if dp.count("/") - base >= 4:
                dns[:] = []
            locks += [os.path.join(dp, f) for f in fns if f in LOCKFILES]
    return sorted(set(locks)), sorted(set(wps)), denied[0]


def wp_plugins(root):
    plugins = []
    pdir = os.path.join(root, "wp-content", "plugins")
    try:
        slugs = sorted(os.listdir(pdir))
    except OSError:
        return plugins
    for slug in slugs:
        d = os.path.join(pdir, slug)
        if not os.path.isdir(d):
            continue
        for f in sorted(glob.glob(os.path.join(d, "*.php"))):
            head = read_text(f, 8192)
            name = re.search(r"Plugin Name:\s*(.+)", head)
            ver = re.search(r"(?mi)^[\s*#@]*Version:\s*([0-9][^\s]*)", head)
            if name and ver:
                plugins.append((slug, name.group(1).strip(), ver.group(1)))
                break
    return plugins


def wordpress_server(root):
    out = []
    m = re.search(r"\$wp_version\s*=\s*'([^']+)'", read_text(os.path.join(root, "wp-includes", "version.php")))
    if m:
        out.append(judge_runtime("워드프레스", "wordpress", m.group(1), 2, root))

    plugins = wp_plugins(root)
    if not plugins:
        return out

    def latest(p):
        return p, get_json("https://api.wordpress.org/plugins/info/1.2/?action=plugin_information"
                           "&request%5Bslug%5D=" + urllib.parse.quote(p[0]))

    with ThreadPoolExecutor(8) as ex:
        answers = list(ex.map(latest, plugins))

    behind, closed, unknown = [], [], []
    for (slug, name, ver), info in answers:
        if not isinstance(info, dict):
            unknown.append(name)
        elif info.get("closed") or info.get("error") == "closed":
            closed.append("%s %s · 배포 중단%s" % (name, ver, " (%s)" % info["reason"] if info.get("reason") else ""))
        elif info.get("version"):
            if vtuple(ver) < vtuple(info["version"]):
                behind.append("%s %s → %s" % (name, ver, info["version"]))
        else:
            unknown.append(name)
    tail = ["wordpress.org 에 없는 플러그인 %d개는 비교하지 못했습니다: %s" % (len(unknown), ", ".join(unknown[:8]))] \
        if unknown else []
    if closed:
        out.append(Finding(DANGER, "배포가 중단된 워드프레스 플러그인이 %d개 있습니다" % len(closed),
                           ["wordpress.org 가 내려 버린 플러그인입니다.",
                            "보안 문제 때문에 내려지는 경우가 많고, 더는 고쳐지지 않습니다."],
                           "배포 중단된 플러그인을 지우고 대신할 플러그인으로 바꿔 주십시오.",
                           [root] + closed))
    if behind:
        out.append(Finding(WARN, "업데이트가 밀린 워드프레스 플러그인이 %d개 있습니다" % len(behind),
                           ["워드프레스가 해킹당하는 가장 흔한 길이 오래된 플러그인입니다.",
                            "새 버전에 보안 수정이 들어 있을 수 있습니다."],
                           "워드프레스 관리자 화면에서 플러그인을 모두 업데이트해 주십시오.",
                           [root] + behind + tail))
    elif not closed:
        out.append(Finding(OK, "워드프레스 플러그인 %d개가 모두 최신입니다" % (len(plugins) - len(unknown)),
                           "wordpress.org 에 올라온 최신 버전과 같습니다.", detail=[root] + tail))
    return out


def docker_finding():
    if not which("docker"):
        return None
    rc, out = run(["docker", "ps", "--format", "{{.Names}} {{.Image}}"])
    if rc != 0:
        return Finding(UNKNOWN, "도커 컨테이너는 확인하지 못했습니다",
                       "컨테이너 목록을 볼 권한이 없습니다.", detail=["root 로 실행하면 목록까지는 볼 수 있습니다."])
    hits = [l for l in out.splitlines() if re.search(r"php|node|wordpress|next", l, re.I)]
    if not hits:
        return None
    return Finding(UNKNOWN, "컨테이너 안의 PHP·Node.js 는 점검하지 못했습니다",
                   ["도커 컨테이너 안에서 도는 프로그램은 이 점검이 들여다보지 않습니다.",
                    "컨테이너 이미지를 새로 받아 다시 띄우는지 외주 업체에 확인해 보십시오."], detail=hits)


def server_check(extra):
    user = os.environ.get("USER") or str(os.geteuid())
    rep = Report("서버 점검", "%s (%s 계정)" % (socket.gethostname(), user))

    progress("운영체제 확인")
    rep.add(os_finding())
    progress("밀린 업데이트 확인")
    rep.add(updates_finding())

    progress("PHP 확인")
    phps = php_binaries()
    rep.add(runtime_findings("PHP", "php", 2, phps))
    rep.add(php_settings_findings(phps))

    progress("Node.js 확인")
    procs = processes()
    rep.add(runtime_findings("Node.js", "nodejs", 1, node_binaries(procs)))
    rep.add(stale_finding(procs))

    progress("사이트 폴더 찾는 중")
    locks, wps, denied = find_projects(extra, procs)
    for root in wps:
        progress("워드프레스 확인: " + root)
        rep.add(wordpress_server(root))
    for lock in locks:
        progress("부품 확인: " + lock)
        eco, pkgs = parse_lockfile(os.path.basename(lock), read_text(lock, 64 * 1024 * 1024))
        if pkgs:
            rep.add(deps_finding(os.path.dirname(lock), os.path.basename(lock), eco, pkgs))
    if not locks and not wps:
        rep.add(Finding(UNKNOWN, "사이트 폴더를 찾지 못했습니다", "사이트가 있는 폴더를 직접 알려 주십시오.",
                        detail=["예: python3 sitecheck.py --server /var/www/mysite"]))
    rep.add(docker_finding())

    if os.geteuid() != 0 and denied:
        rep.notes.append("root 권한 없이 실행해서 다른 계정의 폴더 %d곳은 읽지 못했습니다. "
                         "sudo 로 실행하면 더 넓게 봅니다." % denied)
    rep.notes.append("점검하지 않는 것: 컨테이너 내부, 방화벽·열린 포트, 사이트 코드 자체의 버그.")
    return rep


# ─── 출력 ────────────────────────────────────────────────────────────

def letter_items(reports):
    """요청문 본문 — 고칠 항목마다 제목·요청·근거. 고칠 것이 없으면 []."""
    todo = [f for r in reports for f in r.sorted() if f.level in (DANGER, WARN) and f.ask]
    L = []
    for i, f in enumerate(todo, 1):
        L.append("%d. [%s] %s" % (i, f.level, f.title))
        L.append("   요청: " + f.ask)
        for j, d in enumerate(f.detail):
            L.append(("   근거: " if j == 0 else "         ") + d)
        L.append("")
    return L


def letter_lines(reports):
    items = letter_items(reports)
    if not items:
        return []
    return (["안녕하세요.",
             "%s 보안 점검에서 아래 항목이 나왔습니다." % ", ".join(r.target for r in reports),
             "확인하고 조치해 주십시오.", ""] + items +
            ["조치가 끝나면 알려 주십시오.", "같은 점검을 다시 돌려 확인하겠습니다.", "", CREDIT])


def render_text(reports):
    L = []
    for rep in reports:
        L += ["=" * 64, " 사이트 보안 점검 — " + rep.kind, " 대상  " + rep.target, " 시각  " + rep.when, "=" * 64,
              "", " " + rep.headline(), " " + rep.counts()]
        for f in rep.sorted():
            L += ["", "[%s] %s" % (f.level, f.title)]
            L += ["    " + s for s in f.plain]
            if f.ask:
                L.append("    요청할 말: " + f.ask)
            L += ["    · " + d for d in f.detail]
        if rep.notes:
            L += ["", "알아 두기"] + ["  - " + n for n in rep.notes]
        L.append("")
    letter = letter_lines(reports)
    if letter:
        L += ["-" * 64, " 외주 업체에 보낼 요청문 — 아래를 그대로 복사해 보내십시오", "-" * 64, ""] + letter
    else:
        L.append(CREDIT)
    return "\n".join(L) + "\n"


HTML_CSS = """
body{font-family:-apple-system,"Segoe UI","Malgun Gothic",sans-serif;background:#f6f7f9;color:#191f28;
margin:0;padding:24px 16px;line-height:1.6}
main{max-width:760px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
.meta{color:#6b7684;font-size:14px;margin-bottom:16px}
.head{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;font-size:17px;font-weight:600}
.head small{display:block;font-weight:400;color:#6b7684;font-size:14px}
.item{background:#fff;border-radius:12px;padding:16px;margin-bottom:8px}
.item h3{font-size:16px;margin:0 0 6px}
.lv{display:inline-block;font-size:12px;font-weight:700;border-radius:6px;padding:2px 8px;margin-right:6px}
.lv-위험{background:#fdecea;color:#c5221f}.lv-주의{background:#fef3e0;color:#9a5b00}
.lv-확인{background:#eceff1;color:#4e5968}.lv-문제없음{background:#e6f4ea;color:#137333}
.item p{margin:0}.ask{margin-top:8px;font-weight:600}
.det{margin:8px 0 0;padding-left:18px;color:#6b7684;font-size:13px;word-break:break-all}
.notes{color:#6b7684;font-size:14px;margin:12px 0 28px}
textarea{width:100%;box-sizing:border-box;min-height:320px;font:13px/1.6 ui-monospace,Consolas,monospace;
border:1px solid #d1d6db;border-radius:12px;padding:12px}
"""


def render_html(reports):
    e = html.escape
    P = ['<!doctype html><html lang="ko"><head><meta charset="utf-8">'
         '<meta name="viewport" content="width=device-width,initial-scale=1">'
         '<title>사이트 보안 점검</title><style>%s</style></head><body><main>' % HTML_CSS]
    for rep in reports:
        P.append("<h1>사이트 보안 점검 — %s</h1><div class=meta>%s · %s</div>" % (e(rep.kind), e(rep.target), e(rep.when)))
        P.append("<div class=head>%s<small>%s</small></div>" % (e(rep.headline()), e(rep.counts())))
        for f in rep.sorted():
            P.append('<div class=item><h3><span class="lv lv-%s">%s</span>%s</h3>'
                     % (e(f.level.split()[0]), e(f.level), e(f.title)))
            P.append("".join("<p>%s</p>" % e(s) for s in f.plain))
            if f.ask:
                P.append("<p class=ask>요청할 말: %s</p>" % e(f.ask))
            if f.detail:
                P.append("<ul class=det>%s</ul>" % "".join("<li>%s</li>" % e(d) for d in f.detail))
            P.append("</div>")
        if rep.notes:
            P.append("<div class=notes>%s</div>" % "<br>".join(e(n) for n in rep.notes))
    letter = letter_lines(reports)
    if letter:
        P.append("<h1>외주 업체에 보낼 요청문</h1><div class=meta>그대로 복사해 보내십시오.</div>")
        P.append("<textarea readonly>%s</textarea>" % e("\n".join(letter)))
    P.append('<div class=notes>sitecheck %s 로 점검했습니다 · <a href="%s">%s</a></div>' % (VERSION, HOME, HOME))
    P.append("</main></body></html>")
    return "".join(P)


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")
        except AttributeError:
            pass
    ap = argparse.ArgumentParser(
        prog="sitecheck",
        description="외주로 만든 사이트의 PHP·Node.js 보안 점검. 본인이 운영하거나 관리를 맡은 사이트에만 쓰십시오.",
        epilog="예)\n  python3 sitecheck.py https://example.com\n"
               "  python3 sitecheck.py --server\n"
               "  python3 sitecheck.py --server /var/www/mysite --html report.html",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", nargs="?", help="바깥에서 점검할 사이트 주소")
    ap.add_argument("--server", nargs="*", metavar="폴더",
                    help="이 서버를 안에서 점검합니다. 사이트 폴더를 덧붙이면 그곳도 봅니다.")
    ap.add_argument("--html", metavar="파일", help="결과를 HTML 파일로도 저장합니다")
    ap.add_argument("--version", action="version", version="sitecheck " + VERSION)
    args = ap.parse_args()

    if args.server is None and not args.url:
        ap.print_help()
        return 64
    if args.server is not None and os.name == "nt":
        sys.stderr.write("서버 점검은 리눅스 서버에서 실행합니다.\n")
        return 64

    reports = []
    if args.url:
        reports.append(remote_check(args.url))
    if args.server is not None:
        reports.append(server_check(args.server))

    sys.stdout.write(render_text(reports))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(reports))
        sys.stderr.write("· HTML 결과를 저장했습니다: %s\n" % args.html)

    levels = [f.level for r in reports for f in r.findings]
    return 2 if DANGER in levels else 1 if WARN in levels else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
