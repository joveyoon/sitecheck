#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sitecheck 웹 — 서버에 들어가지 못하는 사이트 주인이 주소만 넣고 바깥 점검을 돌린다.

결과마다 고유 링크가 생긴다. 주인은 그 링크를 외주 업체에 보내고, 업체는 고친 뒤 같은 링크에서
「다시 점검」을 눌러 항목이 사라지는 것을 보여 준다.

  python3 web/app.py

환경 변수
  SITECHECK_PORT    듣는 포트 (기본 8130, 127.0.0.1 에서만)
  SITECHECK_PUBLIC  밖에서 보이는 주소. 요청문 링크와 화면 안 링크에 쓴다 (기본 http://127.0.0.1:8130)
  SITECHECK_DB      결과 저장 파일 (기본 web/sitecheck.db)

표준 라이브러리만 쓴다. 다른 사이트를 대신 찾아가는 서비스라 아래를 지킨다.
  - 공개 인터넷 주소에만 접속한다 (getaddrinfo 를 감싸 사설·루프백 주소를 걸러 낸다 — 리다이렉트도 막힌다)
  - 80·443 포트만 받는다
  - IP 마다 시간당 점검 횟수, 사이트마다 1분에 한 번
"""

import html
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import sys
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sitecheck as sc  # noqa: E402

PORT = int(os.environ.get("SITECHECK_PORT", "8130"))
PUBLIC = os.environ.get("SITECHECK_PUBLIC", "http://127.0.0.1:%d" % PORT).rstrip("/")
PREFIX = urllib.parse.urlsplit(PUBLIC).path.rstrip("/")
DB_PATH = os.environ.get("SITECHECK_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sitecheck.db"))

ONE_LINER = ("curl -fsSL https://raw.githubusercontent.com/joveyoon/sitecheck/v%s/sitecheck.py"
             " | python3 - --server" % sc.VERSION)

PER_IP_HOUR = 10         # IP 하나가 한 시간에 새로 맡길 수 있는 점검
SAME_SITE_GAP = 60       # 같은 사이트는 이 간격(초)보다 자주 점검하지 않는다
MAX_WAITING = 20         # 대기열이 이보다 길면 새 점검을 받지 않는다
WORKERS = threading.Semaphore(3)
CACHE_TTL = 3600         # 버전·취약점 정보를 다시 받아 오는 간격


# ─── 공개 주소에만 접속 ─────────────────────────────────────────────

_getaddrinfo = socket.getaddrinfo


def _public_only(host, *args, **kwargs):
    res = _getaddrinfo(host, *args, **kwargs)
    ok = [r for r in res if ipaddress.ip_address(r[4][0].split("%")[0]).is_global]
    if not ok:
        raise socket.gaierror("공개 인터넷 주소가 아니에요: %s" % host)
    return ok


def normalize(url):
    """입력한 주소를 점검할 기준 주소로. 점검할 수 없으면 ValueError(사용자에게 보일 문장)."""
    url = (url or "").strip()
    if not url:
        raise ValueError("사이트 주소를 넣어 주세요.")
    if "://" not in url:
        url = "https://" + url
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        raise ValueError("주소를 알아보지 못했어요.")
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("주소를 알아보지 못했어요.")
    if port not in (None, 80, 443):
        raise ValueError("80·443 포트로 열리는 사이트만 점검할 수 있어요.")
    try:
        host = u.hostname.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("주소를 알아보지 못했어요.")
    try:
        socket.getaddrinfo(host, 443)
    except OSError:
        raise ValueError("이 주소는 점검할 수 없어요. 인터넷에 공개된 사이트 주소인지 확인해 주세요.")
    return "%s://%s" % (u.scheme, host if port is None else "%s:%d" % (host, port))


# ─── 저장 ────────────────────────────────────────────────────────────

_db_lock = threading.Lock()
_db = None


def db(sql, args=(), one=False):
    with _db_lock:
        cur = _db.execute(sql, args)
        rows = cur.fetchall()
        _db.commit()
    if one:
        return rows[0] if rows else None
    return rows


def open_db():
    global _db
    _db = sqlite3.connect(DB_PATH, check_same_thread=False)
    _db.row_factory = sqlite3.Row
    _db.executescript("""
        create table if not exists report (
            token text primary key, url text not null, created real not null);
        create table if not exists run (
            id integer primary key autoincrement, token text not null,
            started real not null, finished real, status text not null, data text);
        create index if not exists run_token on run(token);
    """)
    # 프로세스가 점검 도중 멈췄다면 그 점검은 다시 오지 않는다
    _db.execute("update run set status='failed', data=? where status in ('queued','running')",
                (json.dumps({"error": "점검 서버가 다시 시작돼서 멈췄어요. 다시 점검해 주세요."}),))
    _db.commit()


def report_to_dict(rep):
    return {"kind": rep.kind, "target": rep.target, "when": rep.when, "notes": rep.notes,
            "findings": [{"level": f.level, "title": f.title, "plain": f.plain, "ask": f.ask,
                          "detail": f.detail} for f in rep.findings]}


def report_from_dict(d):
    rep = sc.Report(d["kind"], d["target"])
    rep.when, rep.notes = d["when"], d["notes"]
    rep.findings = [sc.Finding(x["level"], x["title"], x["plain"], x["ask"], x["detail"]) for x in d["findings"]]
    return rep


# ─── 점검 실행 ───────────────────────────────────────────────────────

_cache_born = [time.time()]


def execute(run_id, url):
    with WORKERS:
        db("update run set status='running' where id=?", (run_id,))
        if time.time() - _cache_born[0] > CACHE_TTL:
            sc._cache.clear()
            _cache_born[0] = time.time()
        try:
            data, status = json.dumps(report_to_dict(sc.remote_check(url)), ensure_ascii=False), "done"
        except BaseException as e:  # SystemExit 도 여기서 멈춘다 — 점검 하나가 서버를 끄면 안 된다
            data, status = json.dumps({"error": "점검하다가 멈췄어요: %s" % e}, ensure_ascii=False), "failed"
        db("update run set status=?, data=?, finished=? where id=?", (status, data, time.time(), run_id))


def start_run(token, url):
    cur = None
    with _db_lock:
        cur = _db.execute("insert into run (token, started, status) values (?, ?, 'queued')", (token, time.time()))
        _db.commit()
    threading.Thread(target=execute, args=(cur.lastrowid, url), daemon=True).start()


_ip_hits = defaultdict(deque)
_site_last = {}
_limit_lock = threading.Lock()


LIMITS = {
    "busy": "지금 점검이 몰려 있어요. 잠시 뒤에 다시 해 주세요.",
    "ip": "한 시간에 %d번까지 점검할 수 있어요. 잠시 뒤에 다시 해 주세요." % PER_IP_HOUR,
    "site": "같은 사이트를 방금 점검했어요. 1분 뒤에 다시 해 주세요.",
}


def allow_new(ip, url):
    """새 점검을 받아도 되는가. 안 되면 LIMITS 의 키."""
    now = time.time()
    waiting = db("select count(*) n from run where status in ('queued','running')", one=True)["n"]
    if waiting >= MAX_WAITING:
        return "busy"
    with _limit_lock:
        hits = _ip_hits[ip]
        while hits and now - hits[0] > 3600:
            hits.popleft()
        if len(hits) >= PER_IP_HOUR:
            return "ip"
        if now - _site_last.get(url, 0) < SAME_SITE_GAP:
            return "site"
        hits.append(now)
        _site_last[url] = now
    return None


# ─── 화면 ────────────────────────────────────────────────────────────

e = html.escape

CSS = sc.HTML_CSS + """
.lead{font-size:17px;color:#333d4b;margin:0 0 4px}
form.check{display:flex;gap:8px;margin-top:16px}
input[type=text]{flex:1;min-width:0;font-size:16px;padding:12px 14px;border:1px solid #d1d6db;border-radius:10px;background:#fff}
button{font-size:16px;padding:12px 18px;border:0;border-radius:10px;background:#3182f6;color:#fff;font-weight:600;cursor:pointer;white-space:nowrap}
button.sub{background:#e8f3ff;color:#1b64da}
.agree{margin:10px 0 0;font-size:14px;color:#4e5968}
.box{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px}
.box h2{font-size:17px;margin:0 0 8px}
.box ol,.box ul{margin:0;padding-left:20px}
.fixed{background:#e6f4ea}
.err{background:#fdecea;color:#c5221f}
.row{display:flex;gap:8px;margin-top:8px;align-items:center}
.row input{flex:1;font-size:14px;padding:10px;border:1px solid #d1d6db;border-radius:8px;min-width:0}
textarea{min-height:240px}
.hist{font-size:14px;color:#4e5968}
.foot{color:#8b95a1;font-size:13px;margin:24px 0}
.foot a{color:#8b95a1}
"""

COPY_JS = """
document.querySelectorAll('[data-copy]').forEach(function(b){
  b.addEventListener('click', function(){
    var t = document.getElementById(b.getAttribute('data-copy'));
    var done = function(){ var o = b.textContent; b.textContent = '복사했어요'; setTimeout(function(){ b.textContent = o; }, 1500); };
    if (navigator.clipboard) { navigator.clipboard.writeText(t.value).then(done, function(){ t.select(); document.execCommand('copy'); done(); }); }
    else { t.select(); document.execCommand('copy'); done(); }
  });
});
"""


def page(title, body, index=False, refresh=None, desc=None):
    head = ['<!doctype html><html lang="ko"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width,initial-scale=1">',
            "<title>%s</title>" % e(title)]
    if desc:
        head.append('<meta name="description" content="%s">' % e(desc))
    if not index:
        head.append('<meta name="robots" content="noindex,nofollow">')
    if refresh:
        head.append('<meta http-equiv="refresh" content="%d">' % refresh)
    head.append("<style>%s</style></head><body><main>" % CSS)
    foot = ('<div class=foot>sitecheck %s · <a href="%s" rel="noopener">소스 코드</a></div>'
            % (sc.VERSION, sc.HOME))
    return "".join(head) + body + foot + "<script>%s</script></main></body></html>" % COPY_JS


def home_page(error=None, url=""):
    b = ["<h1>홈페이지 보안 점검</h1>",
         "<p class=lead>서버에 들어가지 않아도 돼요.</p>",
         "<p class=lead>사이트 주소만 넣으면 밖에서 보이는 보안 문제를 찾아요.</p>"]
    if error:
        b.append("<div class='box err'>%s</div>" % e(error))
    b.append('<form class=check method=post action="%s/check">'
             '<input type=text name=url placeholder="https://내사이트.co.kr" value="%s" required '
             'autocomplete=url inputmode=url aria-label="사이트 주소">'
             "<button>점검하기</button></form>" % (PREFIX, e(url)))
    b.append("<p class=agree>본인이 운영하거나 관리를 맡은 사이트만 점검해 주세요.</p>")
    b.append("<div class=box style='margin-top:20px'><h2>이렇게 써요</h2><ol>"
             "<li>사이트 주소를 넣고 점검해요. 30초쯤 걸려요.</li>"
             "<li>결과 화면의 링크와 요청문을 외주 업체에 보내요.</li>"
             "<li>업체가 고친 뒤 같은 링크에서 「다시 점검」을 누르면, 고쳐진 항목이 따로 보여요.</li>"
             "</ol></div>")
    b.append("<div class=box><h2>보는 것</h2><ul>"
             "<li>보안 인증서와 https 연결</li>"
             "<li>밖에서 열리면 안 되는 파일 29곳 (비밀 설정, 소스 코드 저장소, 백업 파일 등)</li>"
             "<li>밖으로 드러난 프로그램 버전과 브라우저 보호 설정</li>"
             "<li>워드프레스 버전, 관리자 아이디 노출, 비밀번호 대입 통로</li>"
             "</ul><p style='margin-top:8px;color:#6b7684;font-size:14px'>"
             "서버 안쪽(PHP·Node.js 버전, 사이트 부품)은 밖에서 볼 수 없어요.<br>"
             "그래서 요청문에 서버 점검 요청을 함께 넣어 드려요.</p></div>")
    return page("홈페이지 보안 점검 — 주소만 넣으면 돼요 | sitecheck", "".join(b), index=True,
                desc="서버에 들어가지 않아도 사이트 주소만으로 홈페이지·워드프레스 보안 문제를 찾고, "
                     "외주 업체에 보낼 요청문까지 만들어 드려요.")


def finding_html(f):
    p = ['<div class=item><h3><span class="lv lv-%s">%s</span>%s</h3>' % (e(f.level.split()[0]), e(f.level), e(f.title))]
    p += ["<p>%s</p>" % e(s) for s in f.plain]
    if f.ask:
        p.append("<p class=ask>요청할 말: %s</p>" % e(f.ask))
    if f.detail:
        p.append("<ul class=det>%s</ul>" % "".join("<li>%s</li>" % e(d) for d in f.detail))
    p.append("</div>")
    return "".join(p)


def norm_title(t):
    return re.sub(r"\d+(?:\.\d+)*", "#", t)


def issues(rep):
    return {norm_title(f.title): f for f in rep.findings if f.level in (sc.DANGER, sc.WARN)}


def reachable(rep):
    return not any(f.title == "사이트에 접속하지 못했어요" for f in rep.findings)


def web_letter(rep, link):
    items = sc.letter_items([rep])
    L = ["안녕하세요.", "%s 보안 점검 결과를 보내 드려요." % rep.target]
    if items:
        L += ["밖에서 점검해 보니 아래 항목이 나왔어요.", "확인하고 조치해 주세요.", ""] + items
    else:
        L += ["밖에서 점검했을 때는 문제가 나오지 않았어요.", ""]
    L += ["서버 안쪽도 점검해 주세요.",
          "사이트 서버에서 아래 한 줄을 돌리고, 나온 결과를 그대로 보내 주세요.",
          ONE_LINER, "",
          "조치가 끝나면 아래 링크에서 「다시 점검」을 눌러 주세요.",
          "고친 항목은 「고쳐진 항목」으로 따로 보여요.",
          link, "", sc.CREDIT]
    return "\n".join(L)


def result_page(token, notice=None):
    r = db("select * from report where token=?", (token,), one=True)
    if not r:
        return None
    runs = db("select * from run where token=? order by id", (token,))
    latest = runs[-1]
    host = urllib.parse.urlsplit(r["url"]).hostname
    link = "%s/r/%s" % (PUBLIC, token)
    b = ["<h1>%s 보안 점검</h1>" % e(host)]
    b.append("<div class=meta>%s · 처음 점검 %s</div>" % (e(r["url"]), time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created"]))))
    if notice:
        b.append("<div class='box err'>%s</div>" % e(notice))

    if latest["status"] in ("queued", "running"):
        b.append("<div class=head>점검하고 있어요.<small>30초쯤 걸려요. 끝나면 이 화면이 저절로 바뀌어요.</small></div>")
        return page("%s 점검 중" % host, "".join(b), refresh=3)

    done = [x for x in runs if x["status"] == "done"]
    if latest["status"] == "failed":
        msg = json.loads(latest["data"] or "{}").get("error", "점검하다가 멈췄어요.")
        b.append("<div class='box err'>%s</div>" % e(msg))
        b.append(recheck_form(token, "다시 점검"))
        if not done:
            return page("%s 점검" % host, "".join(b))

    rep = report_from_dict(json.loads(done[-1]["data"]))
    first = report_from_dict(json.loads(done[0]["data"]))
    b.append("<div class=head>%s<small>%s</small></div>" % (e(rep.headline()), e(rep.counts())))
    if latest["status"] != "failed":
        b.append(recheck_form(token, "다시 점검"))

    if len(done) > 1 and reachable(rep):
        now = issues(rep)
        fixed = [f for k, f in issues(first).items() if k not in now]
        if fixed:
            b.append("<div class='box fixed'><h2>고쳐진 항목 %d개</h2><ul>%s</ul></div>"
                     % (len(fixed), "".join("<li>%s</li>" % e(f.title) for f in fixed)))

    b.append("<div class=box><h2>외주 업체에 맡기기</h2><ol>"
             "<li>아래 요청문을 복사해 외주 업체에 보내 주세요.</li>"
             "<li>요청문에 이 결과 링크와 서버 점검 요청이 함께 들어 있어요.</li>"
             "<li>업체가 고친 뒤 「다시 점검」을 누르면 고쳐진 항목이 이 화면에 따로 보여요.</li></ol>"
             "<textarea id=letter readonly>%s</textarea>"
             "<div class=row><button type=button data-copy=letter>요청문 복사</button></div>"
             "<div class=row><input id=link readonly value='%s'><button type=button class=sub data-copy=link>링크 복사</button></div>"
             "</div>" % (e(web_letter(rep, link)), e(link)))

    b += [finding_html(f) for f in rep.sorted()]

    if len(runs) > 1:
        rows = []
        for x in reversed(runs):
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(x["started"]))
            if x["status"] == "done":
                rr = report_from_dict(json.loads(x["data"]))
                rows.append("<li>%s · 위험 %d · 주의 %d</li>" % (when, rr.count(sc.DANGER), rr.count(sc.WARN)))
            else:
                rows.append("<li>%s · 점검 못 함</li>" % when)
        b.append("<div class='box hist'><h2>점검 기록</h2><ul>%s</ul></div>" % "".join(rows))

    notes = rep.notes + ["이 링크를 아는 사람은 누구나 이 결과를 볼 수 있어요. 외주 업체에만 보내 주세요."]
    b.append("<div class=notes>%s</div>" % "<br>".join(e(n) for n in notes))
    return page("%s 보안 점검 결과" % host, "".join(b))


def recheck_form(token, label):
    return ('<form method=post action="%s/r/%s/recheck" style="margin:0 0 12px">'
            '<button class=sub>%s</button></form>' % (PREFIX, e(token), e(label)))


# ─── HTTP ────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "sitecheck-web"
    sys_version = ""

    def client_ip(self):
        peer = self.client_address[0]
        if peer in ("127.0.0.1", "::1"):
            return self.headers.get("X-Real-IP") or peer
        return peer

    def send(self, status, body="", ctype="text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                         "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def redirect(self, path):
        self.send(303, "", headers={"Location": PREFIX + path})

    def form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(n, 4096)).decode("utf-8", "replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        if path in ("/", ""):
            return self.send(200, home_page())
        if path == "/healthz":
            return self.send(200, "ok", "text/plain; charset=utf-8")
        m = re.match(r"^/r/([A-Za-z0-9_-]{8,40})$", path)
        if m:
            code = urllib.parse.parse_qs(parts.query).get("n", [""])[0]
            body = result_page(m.group(1), LIMITS.get(code))
            if body:
                return self.send(200, body, headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex"})
        self.send(404, page("찾을 수 없어요", "<h1>찾을 수 없어요</h1><p>주소가 맞는지 확인해 주세요.</p>"))

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/check":
            raw = self.form().get("url", "")
            try:
                url = normalize(raw)
            except ValueError as err:
                return self.send(400, home_page(str(err), raw))
            why = allow_new(self.client_ip(), url)
            if why:
                return self.send(429, home_page(LIMITS[why], raw))
            token = secrets.token_urlsafe(12)
            db("insert into report (token, url, created) values (?, ?, ?)", (token, url, time.time()))
            start_run(token, url)
            return self.redirect("/r/" + token)

        m = re.match(r"^/r/([A-Za-z0-9_-]{8,40})/recheck$", path)
        if m:
            token = m.group(1)
            r = db("select * from report where token=?", (token,), one=True)
            if not r:
                return self.send(404, page("찾을 수 없어요", "<h1>찾을 수 없어요</h1>"))
            last = db("select * from run where token=? order by id desc limit 1", (token,), one=True)
            if last["status"] in ("queued", "running"):
                return self.redirect("/r/" + token)
            why = allow_new(self.client_ip(), r["url"])
            if why:
                return self.redirect("/r/%s?n=%s" % (token, why))
            start_run(token, r["url"])
            return self.redirect("/r/" + token)
        self.send(404, page("찾을 수 없어요", "<h1>찾을 수 없어요</h1>"))

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.client_ip(), fmt % args))


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")
        except AttributeError:
            pass
    socket.getaddrinfo = _public_only
    sc.progress = lambda msg: None
    open_db()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.daemon_threads = True
    sys.stderr.write("sitecheck web %s · http://127.0.0.1:%d · 공개 주소 %s\n" % (sc.VERSION, PORT, PUBLIC))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
