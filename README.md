# sitecheck

외주로 만든 사이트의 보안 점검 도구예요.
PHP·Node.js·워드프레스로 만든 사이트에서 알려진 보안 문제를 찾아요.

> 본인이 운영하거나 관리를 맡은 사이트에만 쓰세요.

## 사이트 주인이시라면

서버에 들어가지 않아도 돼요.
**https://etfindex.co.kr/sitecheck/** 에서 사이트 주소만 넣으세요.

1. 점검이 끝나면 결과 화면에 요청문과 결과 링크가 나와요.
2. 「요청문 복사」를 눌러 외주 업체에 보내 주세요. 서버 안쪽 점검 요청도 함께 들어 있어요.
3. 업체가 고친 뒤 같은 링크에서 「다시 점검」을 누르면, 고쳐진 항목이 따로 보여요.

결과는 이렇게 읽어요.

- 맨 위 한 줄이 요약이에요. 「바로 고쳐야 할 문제가 2개 있어요」처럼 나와요.
- **위험**은 바로 고쳐야 할 것이에요. **주의**는 고치면 좋은 것이에요.
- 결과 링크를 아는 사람은 누구나 결과를 볼 수 있어요. 외주 업체에만 보내 주세요.

## 외주 업체·개발자시라면

사이트가 올라간 리눅스 서버에서 아래 한 줄을 돌려 주세요.
설치하는 것도, 남는 파일도 없어요. 읽기만 하고 설정은 바꾸지 않아요.

```bash
curl -fsSL https://raw.githubusercontent.com/joveyoon/sitecheck/v0.1.3/sitecheck.py | python3 - --server
```

- 출력 전체를 사이트 주인께 보내 주세요. 끝에 `--html report.html` 을 붙이면 파일로도 저장돼요.
- 다른 계정의 폴더까지 보려면 `python3` 앞에 `sudo` 를 붙여요.
- 서버 접속 없이 바깥에서만 보려면 Python 이 있는 아무 컴퓨터에서 주소를 넣어요.

```bash
curl -fsSL https://raw.githubusercontent.com/joveyoon/sitecheck/v0.1.3/sitecheck.py | python3 - https://example.com
```

받은 파일을 확인하고 돌리려면:

```bash
curl -fsSLO https://raw.githubusercontent.com/joveyoon/sitecheck/v0.1.3/sitecheck.py
sha256sum sitecheck.py   # 048b189611640a7892761614a05cd69c09465ca582820f44c6f6db67fffca77e
python3 sitecheck.py --server
```

## 쓰는 법

```bash
# 바깥 점검 — 아무 PC 에서나, 사이트 주소만 있으면 된다
python3 sitecheck.py https://example.com

# 서버 점검 — 사이트가 올라간 리눅스 서버에서
python3 sitecheck.py --server
python3 sitecheck.py --server /var/www/mysite      # 못 찾는 폴더를 직접 알려 줄 때
sudo python3 sitecheck.py --server                 # 다른 계정 폴더까지 보려면

# 결과를 HTML 로도 저장 (외주 업체에 보내기 좋다)
python3 sitecheck.py https://example.com --html report.html

# 서버에 파일을 올리지 않고 내 PC 에서 바로 돌리기
ssh 계정@서버 'python3 - --server' < sitecheck.py
```

종료 코드: 위험이 있으면 `2`, 주의만 있으면 `1`, 없으면 `0`.

## 보는 것

### 바깥 점검
| 항목 | 기준 |
|---|---|
| 보안 인증서 | 올바른가, 만료 20일·7일 전 |
| http → https | http 로 들어오면 https 로 넘겨 주는가 |
| 버전 노출 | `Server`·`X-Powered-By` 헤더의 버전 번호 |
| PHP 버전 | `X-Powered-By` 에 보이면 지원 종료·최신 패치 여부 |
| 브라우저 보호 설정 | HSTS, `X-Content-Type-Options`, 프레임 차단 |
| 새면 안 되는 파일 29곳 | `.env`, `.git`, wp-config 백업, SQL·압축 백업, phpinfo, 잠금 파일, 폴더 목록 등 — 내용까지 확인해 오탐을 거른다 |
| 밖에 보이는 잠금 파일 | `composer.lock`·`package-lock.json` 이 열리면 그 안의 부품 취약점까지 |
| 워드프레스 | 버전, 관리자 아이디 노출(REST API), xmlrpc.php |

### 서버 점검
| 항목 | 기준 |
|---|---|
| 운영체제 | 지원 종료 여부 |
| 밀린 업데이트 | `apt list --upgradable` (보안 저장소 표시) · `dnf check-update` |
| PHP·Node.js 버전 | 지원 종료 · 같은 계열 최신 패치 · Node.js 보안 릴리스 |
| 운영체제 패키지 구분 | Ubuntu·RHEL 공식 패키지는 번호를 올리지 않고 패치하므로 번호 비교를 하지 않는다 (sury·remi·nodesource 는 비교한다) |
| 다시 시작 안 한 프로그램 | 실행 중인 php-fpm·node 가 업데이트 전에 시작됐는가 |
| PHP 위험 설정 | `allow_url_include`, `display_errors`, `expose_php` (php-fpm 기준) |
| 사이트 부품 | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock` → OSV 취약점 DB |
| 워드프레스 | 코어 버전, 플러그인 업데이트 밀림, 배포 중단된 플러그인 |
| 도커 | PHP·Node 컨테이너가 있으면 "안은 못 봤다" 고 알린다 |

사이트 폴더는 nginx·Apache 설정의 root, pm2 저장 목록, 실행 중인 node 의 작업 폴더,
`/var/www`·`/srv`·`/opt`·`/home/*` 를 4단계 깊이까지 찾는다.

## 판정 기준

- **위험** — 지원이 끝났거나, 보안 패치가 나왔는데 안 깔았거나, 비밀이 밖으로 새고 있다
- **주의** — 최신 패치가 아니거나, 공격을 쉽게 만드는 설정이다
- **확인 못 함** — 정보를 가져오지 못했거나 권한이 없다

"보안 패치가 나온 버전" 판정:
- Node.js 는 nodejs.org 의 `security` 표시가 붙은 릴리스가 뒤에 나왔는가
- PHP·워드프레스는 그 계열이 보안 수정만 나오는 시기(endoflife.date `support` 종료)인데 뒤에 패치가 나왔는가

## 웹 버전 직접 띄우기

`web/app.py` 가 https://etfindex.co.kr/sitecheck/ 의 웹 버전이다. 역시 표준 라이브러리만 쓴다 (Python 3.7+).

```bash
SITECHECK_PUBLIC=https://example.com/sitecheck python3 web/app.py   # 127.0.0.1:8130
```

| 환경 변수 | 기본값 | |
|---|---|---|
| `SITECHECK_PORT` | `8130` | 127.0.0.1 에서만 듣는다 |
| `SITECHECK_PUBLIC` | `http://127.0.0.1:8130` | 밖에서 보이는 주소. 요청문 링크·화면 링크에 쓴다 |
| `SITECHECK_DB` | `web/sitecheck.db` | 결과 저장 (SQLite) |

nginx:

```nginx
location = /sitecheck { return 301 /sitecheck/; }
location ^~ /sitecheck/ {
    proxy_pass http://127.0.0.1:8130/;
    proxy_set_header X-Real-IP $remote_addr;
    client_max_body_size 8k;
}
```

남의 사이트를 대신 찾아가는 서비스라 아래를 지킨다.
- 공개 인터넷 주소에만 접속한다. `socket.getaddrinfo` 를 감싸 사설·루프백·링크 로컬 주소를 걸러 내므로 리다이렉트로도 내부망에 닿지 않는다
- 80·443 포트만 받는다
- IP 하나당 시간에 10번, 같은 사이트는 1분에 한 번, 대기열 20
- 결과 화면은 `noindex` — 남의 사이트 약점이 검색에 걸리지 않게 한다

## 어디로 무엇을 보내나요

점검 결과는 화면(과 `--html` 파일)에만 남아요. 어디에도 올리지 않아요.
서버 주소·파일 내용·비밀번호·설정 값은 밖으로 나가지 않아요.
웹 버전은 예외예요 — 결과 링크와 「다시 점검」을 위해 바깥 점검 결과를 웹 서버에 저장해요.

밖으로 나가는 요청은 아래가 전부예요. 모든 요청에 `User-Agent: sitecheck/버전` 이 붙어요.

| 받는 곳 | 보내는 것 | 왜 |
|---|---|---|
| 점검할 사이트 (바깥 점검만) | 첫 화면과 정해진 경로 40곳 안쪽에 GET 요청 | 인증서·헤더·새는 파일 확인 |
| [endoflife.date](https://endoflife.date) | 제품 이름 (`php`, `nodejs`, `wordpress`, `ubuntu` 등) | 지원 기간과 계열별 최신 버전 |
| nodejs.org/dist/index.json | 없음 (목록을 받기만 해요) | Node.js 보안 릴리스 |
| [OSV](https://osv.dev) | 부품 이름과 버전 (예: `next 14.2.33`) | npm·Packagist 부품 취약점 |
| api.wordpress.org | 플러그인 폴더 이름 (예: `akismet`) | 플러그인 최신 버전·배포 중단 |

## 보지 않는 것

컨테이너 내부, 방화벽·열린 포트, 사이트 코드 자체의 버그, wordpress.org 에 없는 유료 플러그인.

## English

**sitecheck** is a zero-dependency security checker for websites built by outsourced developers
(PHP, Node.js, WordPress). It writes the report in plain Korean for non-technical site owners and
ends with a ready-to-send request letter for the developer.

- **Outside check** (`sitecheck.py https://example.com`): TLS certificate, HTTP→HTTPS redirect,
  version-leaking headers, missing security headers, 29 commonly exposed files
  (`.env`, `.git`, `wp-config` backups, SQL/zip dumps, phpinfo, lockfiles, directory listing),
  WordPress version, user enumeration, `xmlrpc.php`.
- **Server check** (`sitecheck.py --server`): OS end-of-life, pending (security) updates,
  PHP/Node.js end-of-life and missing patch releases, processes still running a binary that was
  upgraded underneath them, risky `php.ini` settings, npm/yarn/pnpm/Composer dependencies against
  [OSV](https://osv.dev), outdated or closed WordPress plugins. Read-only.

Single file, Python 3.6+, standard library only. Run it without installing:

```bash
curl -fsSL https://raw.githubusercontent.com/joveyoon/sitecheck/v0.1.3/sitecheck.py | python3 - --server
```

Exit code: `2` if any critical finding, `1` if warnings only, `0` otherwise. MIT licensed.
