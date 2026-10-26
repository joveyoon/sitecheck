# sitecheck

외주로 만든 사이트의 PHP·Node.js 보안 점검.
개발을 모르는 사이트 주인이 읽을 수 있는 말로 결과를 보여 주고,
**외주 업체에 그대로 보낼 요청문**까지 만들어 준다.

> 본인이 운영하거나 관리를 맡은 사이트에만 쓴다.

파일 하나(`sitecheck.py`), 표준 라이브러리만 쓴다 — Python 3.6 이상이면 설치 없이 돈다.
서버 점검은 읽기만 한다. 설정을 바꾸거나 프로그램을 다시 시작하지 않는다.

## 바로 돌리기

서버에 아무것도 설치하지 않고, 파일도 남기지 않는다.

```bash
# 서버 점검 — 사이트가 올라간 리눅스 서버에서
curl -fsSL https://raw.githubusercontent.com/joveyoon/sitecheck/v0.1.0/sitecheck.py | python3 - --server

# 바깥 점검 — Python 이 있는 아무 컴퓨터에서
curl -fsSL https://raw.githubusercontent.com/joveyoon/sitecheck/v0.1.0/sitecheck.py | python3 - https://example.com
```

받은 파일을 확인하고 돌리려면:

```bash
curl -fsSLO https://raw.githubusercontent.com/joveyoon/sitecheck/v0.1.0/sitecheck.py
sha256sum sitecheck.py   # 7c5a0fc3baf810802c12ece214c61a2ed00ff99506df9f14ea16e40c9da303e4
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

## 쓰는 정보

| 출처 | 용도 |
|---|---|
| [endoflife.date](https://endoflife.date) | 운영체제·PHP·Node.js·워드프레스 지원 기간과 계열별 최신 버전 |
| nodejs.org/dist/index.json | Node.js 보안 릴리스 |
| [OSV](https://osv.dev) | npm·Packagist 부품 취약점 |
| api.wordpress.org | 플러그인 최신 버전·배포 중단 |

## 보지 않는 것

컨테이너 내부, 방화벽·열린 포트, 사이트 코드 자체의 버그, wordpress.org 에 없는 유료 플러그인.
