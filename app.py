import threading
import time
import sqlite3
import os
import socket
import re
import smtplib
import ssl
import json
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template,
    flash,
    session,
    g,
    jsonify,
)
from flask import Response
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Any, Dict

DB_PATH = os.environ.get("APP_DB", "app.db")

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "dev-secret")

# Basit başvuru rate limit (IP başına saatlik 3)
ORDER_RATE: dict = {}

# PDF oluşturma için reportlab (varsa) kullan
try:
    from reportlab.pdfgen import canvas  # type: ignore
    from reportlab.lib.pagesizes import A4  # type: ignore
    from reportlab.lib import colors  # type: ignore
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


def jinja_datetime(ts):
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))
    except Exception:
        return ts

app.jinja_env.filters['datetime'] = jinja_datetime


# --------------------------- DB helpers ---------------------------
def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def db_init():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            package TEXT NOT NULL CHECK (package IN ('basic','pro','enterprise')),
            target_url TEXT NOT NULL
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            interval_minutes INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            next_run INTEGER,
            FOREIGN KEY(company_id) REFERENCES companies(id)
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            summary TEXT NOT NULL,
            detail TEXT NOT NULL,
            FOREIGN KEY(company_id) REFERENCES companies(id)
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin'
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            smtp_host TEXT,
            smtp_port INTEGER,
            smtp_user TEXT,
            smtp_pass TEXT,
            smtp_tls INTEGER DEFAULT 1,
            webhook_url TEXT
        );
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            company_id INTEGER,
            plan TEXT NOT NULL CHECK (plan IN ('basic','pro','enterprise')),
            amount INTEGER NOT NULL,
            currency TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('initiated','paid','failed')),
            provider TEXT,
            provider_session_id TEXT,
            receipt_url TEXT,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(company_id) REFERENCES companies(id)
        );
        """
    )
    conn.commit()
    conn.close()


def db_migrate():
    # schedules.next_run sütunu eksikse ekle
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(schedules)")
        cols = [row[1] for row in cur.fetchall()]
        if "next_run" not in cols:
            cur.execute("ALTER TABLE schedules ADD COLUMN next_run INTEGER")
            conn.commit()
        # companies.verified sütunu eksikse ekle
        cur.execute("PRAGMA table_info(companies)")
        ccols = [row[1] for row in cur.fetchall()]
        if "verified" not in ccols:
            cur.execute("ALTER TABLE companies ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
            conn.commit()
        # companies.verify_token ve verify_method kolonlarını ekle
        cur.execute("PRAGMA table_info(companies)")
        ccols = [row[1] for row in cur.fetchall()]
        if "verify_token" not in ccols:
            cur.execute("ALTER TABLE companies ADD COLUMN verify_token TEXT")
            conn.commit()
        cur.execute("PRAGMA table_info(companies)")
        ccols = [row[1] for row in cur.fetchall()]
        if "verify_method" not in ccols:
            cur.execute("ALTER TABLE companies ADD COLUMN verify_method TEXT DEFAULT 'http_file'")
            conn.commit()
        # companies.email_verify_token kolonunu ekle (email link doğrulaması için)
        cur.execute("PRAGMA table_info(companies)")
        ccols = [row[1] for row in cur.fetchall()]
        if "email_verify_token" not in ccols:
            cur.execute("ALTER TABLE companies ADD COLUMN email_verify_token TEXT")
            conn.commit()
        # settings.verification_policy kolonunu ekle
        cur.execute("PRAGMA table_info(settings)")
        scols = [row[1] for row in cur.fetchall()]
        if "verification_policy" not in scols:
            cur.execute("ALTER TABLE settings ADD COLUMN verification_policy TEXT DEFAULT 'http_and_dns'")
            conn.commit()
        # companies.aggressive_pentest kolonunu ekle (opsiyonel ağır test profili)
        cur.execute("PRAGMA table_info(companies)")
        ccols = [row[1] for row in cur.fetchall()]
        if "aggressive_pentest" not in ccols:
            cur.execute("ALTER TABLE companies ADD COLUMN aggressive_pentest INTEGER NOT NULL DEFAULT 0")
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] migrate hata: {e}")


# --------------------------- Test modules ---------------------------
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
}


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    if not raw.startswith("http://") and not raw.startswith("https://"):
        return "https://" + raw
    return raw


def get_host_from_url(u: str) -> str:
    try:
        p = urlparse(u)
        return (p.netloc or p.path or "").lower()
    except Exception:
        return (u or "").lower()


def email_domain(email: str) -> str:
    try:
        return (email or "").split("@")[-1].strip().lower()
    except Exception:
        return ""


def base_domain(host: str) -> str:
    parts = (host or "").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def domains_match(email_dom: str, host: str) -> bool:
    email_dom = (email_dom or "").lower()
    host = (host or "").lower()
    bd_email = base_domain(email_dom)
    bd_host = base_domain(host)
    return (
        email_dom == host or
        host.endswith("." + email_dom) or
        email_dom.endswith("." + host) or
        bd_email == bd_host
    )


def dns_txt_has_token(host: str, token: str, timeout: float = 5.0) -> bool:
    try:
        url = f"https://dns.google/resolve?name={host}&type=TXT"
        r = requests.get(url, timeout=timeout, headers=DEFAULT_HEADERS)
        j = r.json()
        answers = j.get("Answer", [])
        for ans in answers:
            data = ans.get("data", "")
            txt = data.strip().strip('"')
            if token in txt or txt == token:
                return True
        return False
    except Exception:
        return False


def check_security_headers(url: str, timeout: float = 4.0) -> str:
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        headers = r.headers
        security_headers = {
            'Content-Security-Policy': 'CSP',
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'XCTO',
            'X-Frame-Options': 'XFO',
            'X-XSS-Protection': 'XXSS'
        }
        lines = ["[*] Güvenlik Başlıkları", f"[i] HTTP: {r.status_code}"]
        for h, label in security_headers.items():
            lines.append(f"{'[+]' if h in headers else '[-]'} {label} ({h})")
        return "\n".join(lines)
    except Exception as e:
        return f"[!] Başlıklar hata: {e}"

def pentest_baseline(url: str, timeout: float = 4.0) -> str:
    """Güvenli, non-intrusive sızma testi: yaygın yanlış yapılandırma ve ifşa kontrolleri.
    - Hassas dosya/kaynak erişimi (/.env, /.git/HEAD, /server-status, /swagger.json vb.)
    - Dizin listeleme (Index of)
    - CORS wildcard (Access-Control-Allow-Origin: *)
    - Hata/stack trace sızıntısı (basit tetikleyici)
    """
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}"
        lines = ["[*] Baseline Sızma Testi", f"[i] Hedef: {base}"]

        common_paths = [
            "/.env", "/.git/HEAD", "/server-status", "/swagger.json", "/api/docs",
            "/actuator", "/actuator/health", "/debug", "/backup.zip", "/db.sql",
            "/config.php", "/wp-config.php", "/robots.txt",
        ]

        def safe_get(path: str):
            try:
                r = requests.get(base + path, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
                return r
            except Exception:
                return None

        # CORS kontrolü ve Set-Cookie bayrakları
        try:
            r0 = requests.get(base, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            aco = (r0.headers.get('Access-Control-Allow-Origin') or '').strip()
            if aco == '*':
                lines.append("[!] CORS wildcard: Access-Control-Allow-Origin: *")
            sc = (r0.headers.get('Set-Cookie') or '')
            if sc:
                # Bir cookie var ve bayraklar eksikse uyarı ver
                # Basit sezgi: herhangi bir cookie satırında HttpOnly veya Secure yoksa işaretle
                has_http_only = ('httponly' in sc.lower())
                has_secure = ('secure' in sc.lower())
                if not has_http_only or ((parsed.scheme or '').lower() == 'https' and not has_secure):
                    lines.append("[!] Cookie bayrağı eksik: HttpOnly/Secure doğru ayarlanmalı")
        except Exception:
            pass

        # Hassas yollar
        for p in common_paths:
            r = safe_get(p)
            if not r:
                continue
            ctype = (r.headers.get('Content-Type') or '').lower()
            body = (r.text or '')
            if r.status_code == 200:
                if p == "/.git/HEAD" and 'ref:' in body:
                    lines.append(f"[!] Hassas dosya erişilebilir: {p}")
                    lines.append(f"PoC: {base}{p}")
                elif p == "/.env" and ("DB_" in body or "SECRET" in body or "KEY=" in body):
                    lines.append(f"[!] Hassas dosya erişilebilir: {p}")
                    lines.append(f"PoC: {base}{p}")
                elif p in ("/swagger.json", "/api/docs") and ('json' in ctype or 'swagger' in body.lower()):
                    lines.append(f"[!] API dokümantasyonu herkese açık: {p}")
                    lines.append(f"PoC: {base}{p}")
                elif p == "/server-status" and ("Server Status" in body or "Apache" in body):
                    lines.append(f"[!] Sunucu durum sayfası açık: {p}")
                    lines.append(f"PoC: {base}{p}")
                elif p in ("/backup.zip", "/db.sql"):
                    lines.append(f"[!] Yedek/DB dosyası erişilebilir: {p}")
                    lines.append(f"PoC: {base}{p}")
                elif p in ("/config.php", "/wp-config.php"):
                    lines.append(f"[!] Konfigürasyon dosyası herkese açık: {p}")
                    lines.append(f"PoC: {base}{p}")
                elif p == "/robots.txt":
                    lines.append("[i] robots.txt bulundu")

        # Dizin listeleme sezgisi
        for cand in ["/", "/assets/", "/uploads/", "/static/", "/files/"]:
            r = safe_get(cand)
            if not r:
                continue
            if r.status_code == 200 and ("Index of" in (r.text or '')):
                lines.append(f"[!] Dizin listeleme açık: {cand}")
                lines.append(f"PoC: {base}{cand}")

        # Basit hata sızıntısı tetikleyicisi
        try:
            qi = "?test='"
            r_err = requests.get(base + qi, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            bt = (r_err.text or '')
            error_markers = ["SQL syntax", "mysql", "Exception", "Traceback", "NullPointerException", "ORA-", "error on line"]
            if any(m.lower() in bt.lower() for m in error_markers):
                lines.append("[!] Hata sızıntısı: muhtemel SQL/stack trace görüntüleniyor")
        except Exception:
            pass

        return "\n".join(lines)
    except Exception as e:
        return f"[!] Baseline sızma testi hata: {e}"

def pentest_aggressive(url: str, timeout: float = 4.5) -> str:
    """Daha kapsamlı ama yine de güvenli (non-destructive) agresif kontroller.
    - Genişletilmiş hassas dosya ve repo izleri: /.git/config, /.svn/entries, /.hg/., /.DS_Store, /.bash_history
    - Yaygın yedek/konfig uzantıları: .zip/.tar.gz/.bak/.old/.save
    - Framework/dev uçları: /graphql, /console, /admin, /manage, /_profiler
    - Güvenli deneme: HEAD istekleri öncelikli, sonra GET (limitli)
    """
    try:
        p = urlparse(url)
        base = f"{p.scheme or 'https'}://{p.netloc or p.path}"
        lines = ["[*] Agresif Sızma Testi", f"[i] Hedef: {base}"]

        paths = [
            "/.git/config", "/.svn/entries", "/.hg/", "/.DS_Store", "/.bash_history",
            "/config.yaml", "/config.yml", "/settings.py", "/local.settings.json",
            "/backup.tar.gz", "/backup.bak", "/site.old.zip", "/db.backup.sql",
            "/graphql", "/admin", "/manage", "/console", "/_profiler", "/debug/",
        ]

        def try_head_then_get(path: str):
            # Önce HEAD ile hafif kontrol; 405 ise GET dene
            try:
                rh = requests.head(base + path, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
                if rh.status_code == 200:
                    return rh
                if rh.status_code in (403, 401):
                    return rh
            except Exception:
                pass
            try:
                rg = requests.get(base + path, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
                return rg
            except Exception:
                return None

        for path in paths:
            r = try_head_then_get(path)
            if not r:
                continue
            ct = (r.headers.get('Content-Type') or '').lower()
            if r.status_code == 200:
                # İçerik sezgileri
                if any(s in path for s in [".git",".svn",".hg",".DS_Store",".bash_history"]):
                    lines.append(f"[!] Repo/evrak izi erişilebilir: {path}")
                elif any(s in path for s in ["backup",".bak",".old",".tar.gz",".zip",".sql"]):
                    lines.append(f"[!] Yedek/konfig dosyası erişilebilir: {path}")
                elif any(s in path for s in ["config.yaml","config.yml","settings.py","local.settings.json"]):
                    lines.append(f"[!] Konfig dosyası herkese açık: {path}")
                elif any(s in path for s in ["/graphql","/admin","/manage","/console","/_profiler","/debug/"]):
                    lines.append(f"[!] Geliştirici/adm uçları açık: {path}")
            elif r.status_code in (403, 401):
                # Varlık doğrulandı ama yetkisiz
                if any(s in path for s in ["/admin","/manage","/console","/_profiler"]):
                    lines.append(f"[i] Yönetim/dev uçları mevcut (403/401): {path}")

        return "\n".join(lines)
    except Exception as e:
        return f"[!] Agresif sızma testi hata: {e}"


# --------------------------- Advanced analyses ---------------------------
def analyze_tls(url: str, port: int = 443, sock_timeout: float = 3.0) -> str:
    """TLS sürümü, müzakere edilen şifre kümesi ve sertifika geçerliliği/son kullanma analizini yapar.
    Güvenli ve salt-okuma niteliğinde bir kontrol.
    """
    try:
        p = urlparse(url)
        host = p.hostname or p.netloc or p.path
        if not host:
            return f"[!] Geçersiz host: {url}"
        lines = ["[*] TLS Analizi", f"[i] Hedef: {host}:{port}"]
        # TLS bağlan ve sürüm/şifre setini al
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=sock_timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = getattr(ssock, "version", lambda: "unknown")()
                cipher = ssock.cipher()  # (name, protocol, bits)
                lines.append(f"[i] TLS sürümü: {ver}")
                if cipher:
                    name, proto, bits = cipher
                    lines.append(f"[i] TLS şifre seti: {name} / {proto} / {bits} bit")
                    weak = any(x in (name or "").upper() for x in ["RC4","DES","3DES","MD5","NULL","EXPORT"]) or (bits and bits < 128)
                    if weak:
                        lines.append("[!] Zayıf şifre kümesi tespit edildi")
                # Sertifika bilgileri
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter') if cert else None
                if not_after:
                    try:
                        from datetime import datetime
                        exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days = (exp - datetime.utcnow()).days
                        lines.append(f"[i] Sertifika bitiş tarihi: {not_after} (~{days} gün)")
                        if days <= 30:
                            lines.append("[!] Sertifika yakında sona eriyor (≤30 gün)")
                        elif days < 0:
                            lines.append("[!] Sertifika süresi dolmuş")
                    except Exception:
                        lines.append(f"[i] Sertifika bitiş: {not_after}")
        # HSTS ve çakışmalar (HTTP üzerinden kontrol)
        try:
            r = requests.get(f"https://{host}", headers=DEFAULT_HEADERS, timeout=4.0, allow_redirects=True)
            hsts = r.headers.get('Strict-Transport-Security')
            if not hsts:
                lines.append("[-] HSTS (Strict-Transport-Security)")
            else:
                lines.append("[+] HSTS (Strict-Transport-Security)")
        except Exception:
            pass
        return "\n".join(lines)
    except Exception as e:
        return f"[!] TLS analiz hata: {e}"


def analyze_cors(url: str, timeout: float = 4.0) -> str:
    """Detaylı CORS analizi: '*' var mı, hangi endpoint, credentials açık mı, preflight nasıl dönüyor.
    Base URL ve olası '/api' için kontrol yapar.
    """
    try:
        p = urlparse(url)
        base = f"{p.scheme or 'https'}://{p.netloc or p.path}"
        lines = ["[*] CORS Analizi", f"[i] Hedef: {base}"]
        test_orig = "https://evil.example"
        targets = [base]
        if not base.endswith('/api'):
            targets.append(base.rstrip('/') + '/api')

        for t in targets:
            # Preflight (OPTIONS)
            try:
                headers = {
                    **DEFAULT_HEADERS,
                    'Origin': test_orig,
                    'Access-Control-Request-Method': 'POST',
                    'Access-Control-Request-Headers': 'Content-Type'
                }
                ro = requests.options(t, headers=headers, timeout=timeout, allow_redirects=False)
                aco = (ro.headers.get('Access-Control-Allow-Origin') or '').strip()
                acc = (ro.headers.get('Access-Control-Allow-Credentials') or '').strip().lower()
                acm = (ro.headers.get('Access-Control-Allow-Methods') or '').strip()
                if aco:
                    lines.append(f"[i] Preflight: {t} → ACO={aco} ACM={acm} ACC={acc}")
                    if aco == '*':
                        lines.append("[!] CORS wildcard: Access-Control-Allow-Origin: *")
                    if acc in ('true','1'):
                        lines.append("[!] CORS credentials açık (Allow-Credentials: true)")
            except Exception:
                pass
            # GET/POST davranışı
            for method in ('GET','POST','PUT'):
                try:
                    headers = {**DEFAULT_HEADERS, 'Origin': test_orig}
                    if method == 'GET':
                        r = requests.get(t, headers=headers, timeout=timeout, allow_redirects=True)
                    elif method == 'POST':
                        r = requests.post(t, headers=headers, timeout=timeout, allow_redirects=True, data={'x':'1'})
                    else:
                        r = requests.put(t, headers=headers, timeout=timeout, allow_redirects=True, data={'x':'1'})
                    aco = (r.headers.get('Access-Control-Allow-Origin') or '').strip()
                    acc = (r.headers.get('Access-Control-Allow-Credentials') or '').strip().lower()
                    if aco:
                        lines.append(f"[i] {method}: {t} → ACO={aco} ACC={acc}")
                        if aco == '*':
                            lines.append("[!] CORS wildcard: Access-Control-Allow-Origin: *")
                        if acc in ('true','1'):
                            lines.append("[!] CORS credentials açık (Allow-Credentials: true)")
                except Exception:
                    pass
        return "\n".join(lines)
    except Exception as e:
        return f"[!] CORS analiz hata: {e}"


def analyze_html_js(url: str, timeout: float = 4.0) -> str:
    """HTML/JS analizi: inline script sayısı, form action durumları, 3P script kaynakları ve basit risk sezgileri."""
    try:
        p = urlparse(url)
        base = f"{p.scheme or 'https'}://{p.netloc or p.path}"
        r = requests.get(base, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(r.text or '', 'html.parser')
        scripts = soup.find_all('script')
        inline_scripts = [s for s in scripts if not s.get('src')]
        third_party = []
        host = p.hostname or p.netloc or ''
        for s in scripts:
            src = s.get('src')
            if src and '://' in src:
                try:
                    hp = urlparse(src)
                    if hp.hostname and (host not in (hp.hostname or '')):
                        third_party.append(src)
                except Exception:
                    pass
        forms = soup.find_all('form')
        bad_actions = []
        for f in forms:
            act = (f.get('action') or '').strip()
            if not act or act.startswith('http://'):
                bad_actions.append(act or '(boş)')
        # inline event handlers basit sezgi
        inline_events = 0
        for tag in soup.find_all(True):
            for attr in tag.attrs.keys():
                if isinstance(attr, str) and attr.lower().startswith('on'):
                    inline_events += 1
        lines = ["[*] HTML/JS Analizi", f"[i] HTTP: {r.status_code}"]
        lines.append(f"[i] Inline script sayısı: {len(inline_scripts)}")
        if inline_events:
            lines.append(f"[i] Inline event handler sayısı: {inline_events}")
        if bad_actions:
            lines.append(f"[!] Riskli form action: {len(bad_actions)} adet → {', '.join(bad_actions[:3])}")
        if third_party:
            lines.append(f"[i] 3P script kaynakları: {len(third_party)} adet")
        return "\n".join(lines)
    except Exception as e:
        return f"[!] HTML/JS analiz hata: {e}"


def pentest_minimal(url: str, timeout: float = 4.0) -> str:
    """Minimal aktif olmayan (non-destructive) sızma kontrolleri: basit XSS yansıma ve SQLi hata sezgisi."""
    try:
        p = urlparse(url)
        base = f"{p.scheme or 'https'}://{p.netloc or p.path}"
        lines = ["[*] Minimal Pentest", f"[i] Hedef: {base}"]
        # Basit XSS yansıma testi
        try:
            xss_payload = "<script>alert(1)</script>"
            rx = requests.get(base + "?q=" + requests.utils.quote(xss_payload), headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            body = rx.text or ''
            if xss_payload in body:
                lines.append("[!] XSS yansıma: payload içerik içinde ham olarak görünüyor")
        except Exception:
            pass
        # Basit SQLi hata sezgisi — baseline ile paralel ama spesifik endpoint tetikleyicisi
        try:
            rs = requests.get(base + "?id='", headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            bt = rs.text or ''
            markers = ["SQL syntax", "mysql", "Exception", "Traceback", "ORA-", "error on line"]
            if any(m.lower() in bt.lower() for m in markers):
                lines.append("[!] SQL hata sezgisi: muhtemel injection hata detayı görünüyor")
        except Exception:
            pass
        # Dizin brute — hafif kontrol (HEAD)
        for cand in ["/admin/", "/console/", "/manage/", "/debug/", "/.well-known/"]:
            try:
                rh = requests.head(base.rstrip('/') + cand, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
                if rh.status_code in (200, 401, 403):
                    lines.append(f"[i] Panel/kayıt mevcut: {cand} (HTTP {rh.status_code})")
            except Exception:
                pass
        return "\n".join(lines)
    except Exception as e:
        return f"[!] Minimal pentest hata: {e}"


def scan_ports(url: str, ports: dict = None, sock_timeout: float = 0.5) -> str:
    try:
        host = urlparse(url).hostname
        if not host:
            return f"[!] Geçersiz host: {url}"
        default = {80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt'}
        use = ports or default
        lines = ["[*] Port Taraması", f"[i] Hedef: {host}"]
        for p, name in use.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(sock_timeout)
            res = s.connect_ex((host, p))
            if res == 0:
                lines.append(f"[+] {p} ({name}) açık")
            s.close()
        return "\n".join(lines)
    except Exception as e:
        return f"[!] Port hata: {e}"


# --------------------------- OWASP Web/API Security (basic heuristics) ---------------------------
def web_api_security_owasp(url: str, timeout: float = 4.0) -> str:
    """Heuristic OWASP tests: SQLi (error/time-based), XSS reflect, LFI/RFI, traversal, SSRF hint,
    CSRF token presence in forms, simple rate-limit observation. Intended as lightweight, safe checks."""
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}"
        lines = ["[*] Web/API Güvenlik (OWASP Heuristics)", f"[i] Hedef: {base}"]

        def get(path: str):
            try:
                return requests.get(base + path, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            except Exception:
                return None

        # SQLi: error-based marker
        for p in ["/?id=1'", "/?q='"]:
            r = get(p)
            if r and r.status_code == 200:
                body = (r.text or '')
                err_marks = ["SQL syntax", "mysql", "ORA-", "PostgreSQL", "PDOException", "ODBC"]
                if any(m.lower() in body.lower() for m in err_marks):
                    lines.append("[!] SQLi izleri: hata mesajı içeriyor")
                    lines.append(f"PoC: {base}{p}")
                    break

        # SQLi: boolean-based içerik farkı
        try:
            r_true = get("/?id=1 AND 1=1")
            r_false = get("/?id=1 AND 1=2")
            if r_true and r_false and r_true.status_code == 200 and r_false.status_code == 200:
                s1 = len((r_true.text or '').encode('utf-8'))
                s2 = len((r_false.text or '').encode('utf-8'))
                if abs(s1 - s2) > 256:
                    lines.append("[!] SQLi boolean-based içerik farkı")
                    lines.append(f"PoC: {base}/?id=1 AND 1=1 vs AND 1=2 | size {s1} vs {s2}")
        except Exception:
            pass

        # SQLi: time-based (very short sleep to avoid impact)
        try:
            t0 = time.time(); r_ok = get("/?id=1")
            t1 = time.time(); r_slow = get("/?id=1 OR SLEEP(2)-- ")
            t2 = time.time()
            if (r_ok and r_slow) and ((t2 - t1) - (t1 - t0) > 1.5):
                delta = ((t2 - t1) - (t1 - t0))
                lines.append("[!] SQLi time-based şüpheli gecikme")
                lines.append(f"PoC: Δ≈{round(delta,2)}s @ {base}/?id=1 OR SLEEP(2)--")
        except Exception:
            pass

        # Reflected XSS
        xss_payload = "<script>alert(1)</script>"
        r_x = get(f"/?q={requests.utils.quote(xss_payload)}")
        if r_x and r_x.status_code == 200 and xss_payload in (r_x.text or ''):
            lines.append("[!] Reflected XSS: payload çıktı içinde görünüyor")
            lines.append(f"PoC: {base}/?q={requests.utils.quote(xss_payload)}")

        # LFI/RFI & Traversal
        r_lfi = get("/?file=../../etc/passwd")
        if r_lfi and r_lfi.status_code == 200 and "root:x:" in (r_lfi.text or ''):
            preview = "\n".join((r_lfi.text or '').splitlines()[:3])
            lines.append("[!] LFI doğrulandı: /etc/passwd içeriği")
            lines.append(f"PoC: {base}/?file=../../etc/passwd\n{preview}")
        r_trav = get("/?path=../../etc/passwd")
        if r_trav and r_trav.status_code == 200 and "root:x:" in (r_trav.text or ''):
            preview = "\n".join((r_trav.text or '').splitlines()[:3])
            lines.append("[!] Directory traversal doğrulandı: /etc/passwd erişildi")
            lines.append(f"PoC: {base}/?path=../../etc/passwd\n{preview}")

        # SSRF hint (best-effort)
        r_ssrf = get("/?url=http://169.254.169.254/latest/meta-data/")
        if r_ssrf and r_ssrf.status_code == 200 and any(s in (r_ssrf.text or '').lower() for s in ["ami", "hostname", "meta-data"]):
            snippet = "\n".join((r_ssrf.text or '').splitlines()[:3])
            lines.append("[!] SSRF izleri: metadata endpoint içeriği döndü")
            lines.append(f"PoC: {base}/?url=http://169.254.169.254/latest/meta-data/\n{snippet}")

        # CSRF token check in forms
        try:
            r_home = get("/")
            if r_home and r_home.status_code == 200:
                soup = BeautifulSoup(r_home.text, "html.parser")
                forms = soup.find_all("form")
                risky = 0
                for f in forms:
                    method = (f.get("method") or "").lower()
                    if method == "post":
                        has_csrf = any('csrf' in (inp.get('name') or '').lower() for inp in f.find_all('input'))
                        if not has_csrf:
                            risky += 1
                if risky > 0:
                    lines.append(f"[!] CSRF token eksik: {risky} POST formda gözlenmedi")
                    lines.append("PoC: POST form inputlarında csrf adı içeren alan yok")
        except Exception:
            pass

        # Simple rate-limit: burst requests and look for 429
        try:
            got429 = False
            for _ in range(5):
                rr = get("/")
                if rr and rr.status_code == 429:
                    got429 = True; break
            if not got429:
                lines.append("[i] Rate limit gözlenmedi (heuristic)")
        except Exception:
            pass

        return "\n".join(lines)
    except Exception as e:
        return f"[!] OWASP modül hata: {e}"


# --------------------------- Cookie Security Tests ---------------------------
def cookie_security_tests(url: str, timeout: float = 4.0) -> str:
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}"
        lines = ["[*] Cookie Güvenliği", f"[i] Hedef: {base}"]
        try:
            r = requests.get(base + "/", headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            set_cookies = r.headers.get('Set-Cookie', '')
            if set_cookies:
                low = set_cookies.lower()
                if 'httponly' not in low or 'secure' not in low:
                    lines.append("[!] Cookie bayrağı eksik: HttpOnly/Secure eksik olabilir")
                    lines.append(f"PoC: Set-Cookie: {set_cookies}")
                if 'samesite' not in low:
                    lines.append("[i] SameSite bayrağı belirtmemiş")
            else:
                lines.append("[i] Set-Cookie başlığı gözlenmedi")
        except Exception as e:
            lines.append(f"[!] Cookie testi hata: {e}")
        return "\n".join(lines)
    except Exception as e:
        return f"[!] Cookie modül hata: {e}"


# --------------------------- Auth/IDOR & Role Bypass ---------------------------
def auth_idor_tests(url: str, timeout: float = 4.0) -> str:
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}"
        lines = ["[*] Yetkilendirme/IDOR Testleri", f"[i] Hedef: {base}"]

        def head_or_get(path: str):
            try:
                h = requests.head(base + path, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
                if h.status_code in (405, 500):
                    g = requests.get(base + path, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
                    return g
                return h
            except Exception:
                return None

        # Public/private ayrımı ve admin panelleri
        for p in ["/admin", "/manage", "/console", "/dashboard", "/phpmyadmin"]:
            r = head_or_get(p)
            if r and r.status_code in (200, 403, 401):
                lines.append(f"[i] Yetkili uç var: {p} (HTTP {r.status_code})")

        # ID param manipülasyonu (best-effort)
        for p in ["/user?id=1", "/profile?id=1", "/api/users/1", "/api/user?id=1"]:
            r1 = head_or_get(p)
            r2 = head_or_get(p.replace("1", "2"))
            if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
                s1 = len((getattr(r1, 'text', '') or '').encode('utf-8')) if hasattr(r1, 'text') else 0
                s2 = len((getattr(r2, 'text', '') or '').encode('utf-8')) if hasattr(r2, 'text') else 0
                if abs(s1 - s2) > 256:
                    lines.append(f"[!] IDOR şüphesi: {p} çıktısı ID değişiminde farklı (unauth)")

        # JWT decode tamper (heuristic only): arayüzde jwt görüldüyse bilgi ver
        r_root = head_or_get("/")
        if r_root and hasattr(r_root, 'text') and ('eyJ' in (r_root.text or '')):
            lines.append("[i] JWT izleri: sayfada token benzeri dize bulundu (manuel analiz önerilir)")

        return "\n".join(lines)
    except Exception as e:
        return f"[!] Auth/IDOR modül hata: {e}"


# --------------------------- Sensitive Files+ ---------------------------
def sensitive_files_scan_plus(url: str, timeout: float = 4.0) -> str:
    try:
        parsed = urlparse(url)
        base = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}"
        lines = ["[*] Sensitive Files+", f"[i] Hedef: {base}"]
        paths = [
            "/backup.zip", "/backup.rar", "/db.sql", "/dump.sql", "/data.sql", "/backup.tar.gz",
            "/.env", "/.env.local", "/.env.production", "/config.yaml", "/settings.py",
            "/firebase.json", "/aws.json", "/aws-keys.txt", "/keys.json",
            "/.git/config", "/.git/HEAD", "/.svn/entries",
            "/admin/", "/dev/", "/old/", "/test/", "/phpmyadmin/",
            "/uploads/", "/files/", "/storage/",
        ]
        for p in paths:
            try:
                r = requests.get(base + p, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
                if r.status_code == 200:
                    lines.append(f"[!] Erişilebilir yol: {p}")
                    lines.append(f"PoC: {base}{p}")
            except Exception:
                pass
        return "\n".join(lines)
    except Exception as e:
        return f"[!] Sensitive Files+ hata: {e}"



def find_html_comments(url: str, timeout: float = 4.0) -> str:
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        comments = re.findall(r'<!--(.*?)-->', r.text, re.DOTALL)
        lines = ["[*] HTML Yorumları", f"[i] HTTP: {r.status_code}"]
        if not comments:
            lines.append("[i] Yorum yok")
        else:
            lines.append(f"[!] {len(comments)} yorum bulundu")
        return "\n".join(lines)
    except Exception as e:
        return f"[!] Yorum hata: {e}"


def scan_subdomains(url: str, prefixes: list = None, http_timeout: float = 3.0, check_http: bool = False) -> str:
    try:
        host = urlparse(url).hostname
        if not host:
            return f"[!] Geçersiz host: {url}"
        parts = host.split('.')
        base = host
        if len(parts) >= 2:
            cc_tlds = {"uk","tr","br","jp","au"}
            second = {"co","com","gov","edu","net","org"}
            if len(parts) >= 3 and parts[-1] in cc_tlds and parts[-2] in second:
                base = '.'.join(parts[-3:])
            else:
                base = '.'.join(parts[-2:])
        defaults = ['www','mail','ftp','api','dev','test','blog','shop','m','staging','admin','static','cdn']
        cand = prefixes if prefixes else defaults
        lines = ["[*] Subdomain", f"[i] Kök: {base}"]
        found = 0
        for pref in cand:
            sub = f"{pref}.{base}"
            try:
                ip = socket.gethostbyname(sub)
                lines.append(f"[+] {sub} → {ip}")
                found += 1
                if check_http:
                    try:
                        r = requests.get(f"http://{sub}", headers=DEFAULT_HEADERS, timeout=http_timeout)
                        lines.append(f"    [i] HTTP: {r.status_code}")
                    except Exception as e:
                        lines.append(f"    [!] HTTP hata: {e}")
            except Exception:
                pass
        if found == 0:
            lines.append("[i] Varsayılanlarda çözüm yok")
        return "\n".join(lines)
    except Exception as e:
        return f"[!] Subdomain hata: {e}"


# --------------------------- Human-readable findings ---------------------------
def build_human_explanations(detail: str):
    """Parse raw test detail text and produce human-friendly findings with recommendations.
    Returns a list of dicts: {title, explanation, recommendation, severity}.
    """
    items = []
    last_item = None
    if not detail:
        return items
    for raw in detail.splitlines():
        line = raw.strip()
        if not line:
            continue
        prev_len = len(items)
        # Missing security headers
        if line.startswith("[-]"):
            if "CSP" in line:
                items.append({
                    "title": "CSP başlığı eksik",
                    "explanation": "İçerik Güvenliği Politikası (Content-Security-Policy) olmaması XSS gibi saldırıların etkisini artırabilir.",
                    "recommendation": "Nginx: add_header Content-Security-Policy \"default-src 'self';\";\nApache: Header always set Content-Security-Policy \"default-src 'self';\"\nGelişmiş: script-src 'self' 'nonce-<rastgele>'; style-src 'self' 'unsafe-inline';",
                    "severity": "orta"
                })
            elif "HSTS" in line:
                items.append({
                    "title": "HSTS başlığı eksik",
                    "explanation": "Strict-Transport-Security olmaması tarayıcının daima HTTPS kullanmasını garanti etmez.",
                    "recommendation": "Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\nApache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
                    "severity": "orta"
                })
            elif "XCTO" in line or "X-Content-Type-Options" in line:
                items.append({
                    "title": "X-Content-Type-Options eksik",
                    "explanation": "Tarayıcının içerik türlerini tahmin etmesini (MIME sniffing) engelleyen koruma yok.",
                    "recommendation": "Yanıta 'X-Content-Type-Options: nosniff' başlığını ekleyin.",
                    "severity": "düşük"
                })
            elif "XFO" in line or "X-Frame-Options" in line:
                items.append({
                    "title": "X-Frame-Options eksik",
                    "explanation": "Sayfanın iframe içinde yüklenmesini engelleyen koruma yok; clickjacking riski artar.",
                    "recommendation": "'X-Frame-Options: DENY' veya 'SAMEORIGIN' başlığını ekleyin.",
                    "severity": "orta"
                })
            elif "XXSS" in line or "X-XSS-Protection" in line:
                items.append({
                    "title": "X-XSS-Protection eksik",
                    "explanation": "Eski bir koruma olsa da bazı tarayıcılarda temel XSS filtrelemesi sağlar. Modern yaklaşım CSP'dir.",
                    "recommendation": "İmkân dahilinde CSP uygulayın; gerekiyorsa 'X-XSS-Protection: 1; mode=block' ekleyin.",
                    "severity": "düşük"
                })
        # Positive indicators that may still be actionable
        elif line.startswith("[+]"):
            # Açık port formatı: "[+] 443 (HTTPS) açık"
            m_port = re.match(r"^\[\+\]\s*(\d+)\s*\(([^)]+)\)\s*açık", line)
            if m_port:
                p = int(m_port.group(1))
                name = m_port.group(2)
                sev = "orta" if p in (80, 443) else "orta"
                items.append({
                    "title": f"Açık port: {p} ({name})",
                    "explanation": f"Sunucuda {p}/{name} portu dışarıya açık.",
                    "recommendation": "Gerekmiyorsa kapatın. Gerekiyorsa güvenlik duvarı ile IP/servis bazlı erişim kısıtlaması uygulayın; 80 için HTTPS'e yönlendirme, 443 için TLS doğru yapılandırma sağlanmalı.",
                    "severity": sev
                })
            # Subdomain formatı: "[+] sub.domain → ip"
            elif "→" in line:
                try:
                    sub = line.split("[+]")[-1].strip().split("→")[0].strip()
                except Exception:
                    sub = "alt alan"
                items.append({
                    "title": f"Alt alan adı bulundu: {sub}",
                    "explanation": "Yeni/var olan bir alt alan tespit edildi; envanter takibi ve güvenlik kapsamı gerekir.",
                    "recommendation": "Alt alanı envantere ekleyin, ilgili servisi tarayın; gereksizse DNS kaydını kaldırın.",
                    "severity": "bilgi"
                })
        # Explicit warnings
        elif line.startswith("[!]"):
            if "yorum" in line:
                m_cnt = re.search(r"(\d+)\s*yorum", line)
                cnt = m_cnt.group(1) if m_cnt else "bazı"
                items.append({
                    "title": "HTML yorumları mevcut",
                    "explanation": f"Sayfa kaynakta {cnt} adet yorum satırı bulundu; yanlışlıkla hassas bilgi sızabilir.",
                    "recommendation": "Üretim öncesi yorumları kaldırın; asla parola, anahtar veya iç URL'leri yorumlarda tutmayın.",
                    "severity": "düşük"
                })
            elif "hata" in line:
                items.append({
                    "title": "Test sırasında hata",
                    "explanation": "Bazı kontroller çalıştırılırken hata mesajı üretildi.",
                    "recommendation": "Ağ/erişim ayarlarını ve hedef URL doğruluğunu kontrol edin; tekrar deneyin.",
                    "severity": "bilgi"
                })
            elif "Hassas dosya" in line:
                items.append({
                    "title": "Hassas dosya erişimi",
                    "explanation": "\.env, \.git/HEAD, yedek/DB gibi dosyalar herkese açık durumda.",
                    "recommendation": "Dosyaları internetten erişilemez hale getirin; web kökünden taşıyın veya sunucu yapılandırmasıyla engelleyin.",
                    "severity": "yüksek"
                })
            elif "API dokümantasyonu" in line:
                items.append({
                    "title": "Açık API dokümantasyonu",
                    "explanation": "Swagger/OpenAPI dokümanı herkese açık; endpoint ve şema bilgisi sızıyor.",
                    "recommendation": "Üretimde API dokümantasyonunu yetki gerektirir hale getirin veya kapatın.",
                    "severity": "orta"
                })
            elif "Sunucu durum" in line:
                items.append({
                    "title": "Sunucu durum sayfası açık",
                    "explanation": "Apache/NGINX server-status benzeri sayfalar sistem iç bilgisini sızdırır.",
                    "recommendation": "Server-status özelliğini kapatın veya sadece iç erişime sınırlayın.",
                    "severity": "orta"
                })
            elif "Dizin listeleme" in line:
                items.append({
                    "title": "Dizin listeleme aktif",
                    "explanation": "Klasör içerisindeki dosyalar dizin indeksinde listeleniyor.",
                    "recommendation": "Web sunucusunda dizin listelemeyi kapatın; hassas dosyaları taşımayı değerlendirin.",
                    "severity": "orta"
                })
            elif "CORS wildcard" in line:
                items.append({
                    "title": "CORS wildcard",
                    "explanation": "Tüm kaynaklara (*) izin verilmiş; kimlik bilgisi ve veri sızıntısı riski artar.",
                    "recommendation": "Access-Control-Allow-Origin değerini belirli domain(ler) ile sınırlandırın; kimlik bilgisi gerektiren isteklerde '*' kullanmayın.",
                    "severity": "orta"
                })
            elif "Hata sızıntısı" in line:
                items.append({
                    "title": "Hata/stack trace sızıntısı",
                    "explanation": "Uygulama hata detaylarını (SQL/trace) son kullanıcıya gösteriyor.",
                    "recommendation": "Üretimde genel hata sayfası kullanın; ayrıntılı logları yalnızca sunucu tarafında saklayın.",
                    "severity": "yüksek"
                })
            elif "Cookie bayrağı" in line:
                items.append({
                    "title": "Cookie güvenlik bayrakları eksik",
                    "explanation": "Set-Cookie başlıklarında HttpOnly/Secure bayrakları doğru ayarlanmamış.",
                    "recommendation": "Uygulama katmanında: HttpOnly, Secure (HTTPS), SameSite=lax/strict ayarla.\nNginx reverse-proxy: proxy_cookie_path / \"/; HttpOnly; Secure; SameSite=Lax\";",
                    "severity": "orta"
                })
        # PoC yakalama: 'PoC:' satırı bir önceki bulguya kanıt ekler
        elif line.startswith("PoC:") and last_item is not None:
            poc = line.split("PoC:", 1)[1].strip()
            ev = last_item.get("evidence") or {}
            if poc.startswith("http"):
                ev["http_request"] = poc
            else:
                ev["http_response"] = poc
            last_item["evidence"] = ev

        # Yeni bulgu eklendiyse last_item güncelle
        if len(items) > prev_len:
            last_item = items[-1]

    if not items:
        items.append({
            "title": "Temel kontroller temiz",
            "explanation": "Bu taramada kritik bir risk belirtilmedi.",
            "recommendation": "Periyodik otomatik taramaları sürdürün ve değişikliklerde yeniden test edin.",
            "severity": "bilgi"
        })
    return items


# --------------------------- Notification stub ---------------------------
def notify(company_email: str, subject: str, message: str):
    # Ayarlardan SMTP veya webhook yapılandırılmışsa gerçek gönderim yap.
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
        st = cur.fetchone()
        conn.close()
    except Exception:
        st = None

    sent = False
    # SMTP
    try:
        if st and st["smtp_host"] and company_email:
            host = st["smtp_host"]
            port = int(st["smtp_port"] or 587)
            user = st["smtp_user"]
            pw = st["smtp_pass"]
            use_tls = bool(st["smtp_tls"])
            msg = f"From: {user}\nTo: {company_email}\nSubject: {subject}\n\n{message}"
            if use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(host, port, timeout=10) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    if user and pw:
                        server.login(user, pw)
                    server.sendmail(user or "noreply@local", [company_email], msg)
            else:
                with smtplib.SMTP(host, port, timeout=10) as server:
                    if user and pw:
                        server.login(user, pw)
                    server.sendmail(user or "noreply@local", [company_email], msg)
            sent = True
    except Exception as e:
        print(f"[NOTIFY] SMTP hata: {e}")

    # Webhook
    try:
        if st and st["webhook_url"]:
            requests.post(st["webhook_url"], json={
                "email": company_email,
                "subject": subject,
                "message": message,
            }, timeout=5)
            sent = True
    except Exception as e:
        print(f"[NOTIFY] Webhook hata: {e}")

    if not sent:
        # Fallback: konsola yaz
        print(f"[NOTIFY] {company_email} :: {subject} :: {message}")


# --------------------------- Scheduler thread ---------------------------
def run_tests_for_company(company: sqlite3.Row):
    url = normalize_url(company["target_url"])
    package = company["package"]
    sections = []
    # Paketlere göre modülleri seç
    if package in ("basic", "pro", "enterprise"):
        sections.append(check_security_headers(url))
        # OWASP Web/API modülü: temel heuristikler
        sections.append(web_api_security_owasp(url))
        # Sensitive Files+ genişletilmiş tarama
        sections.append(sensitive_files_scan_plus(url))
        # Cookie güvenlik testleri
        sections.append(cookie_security_tests(url))
    if package in ("pro", "enterprise"):
        sections.append(scan_ports(url))
        sections.append(find_html_comments(url))
        sections.append(pentest_baseline(url))
        # Gelişmiş analizler
        sections.append(analyze_tls(url))
        sections.append(analyze_cors(url))
        sections.append(analyze_html_js(url))
        sections.append(pentest_minimal(url))
        # Auth/IDOR ve rol atlatma testleri
        sections.append(auth_idor_tests(url))
    if package == "enterprise":
        sections.append(scan_subdomains(url))
        try:
            # Şirket opt-in ise agresif profili ekle
            if ("aggressive_pentest" in company.keys()) and int(company["aggressive_pentest"]) == 1:
                sections.append(pentest_aggressive(url))
        except Exception:
            pass
    summary = f"Paket: {package} | Hedef: {url}"
    detail = "\n\n".join(sections)
    # Kaydet
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO results(company_id, created_at, summary, detail) VALUES (?,?,?,?)",
        (company["id"], int(time.time()), summary, detail)
    )
    conn.commit()
    conn.close()
    # Basit tehdit sezgisi: satırda "[-]" varsa bildir
    if "[-]" in detail or "[!]" in detail:
        try:
            email = (company["email"] if "email" in company.keys() else "")
        except Exception:
            email = ""
        notify(email, "Güvenlik Uyarısı", "Tarama çıktısında potansiyel sorunlar tespit edildi.")


def scheduler_loop(stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            now = int(time.time())
            conn = db_connect()
            cur = conn.cursor()
            cur.execute(
                """
                SELECT s.id, s.company_id, s.interval_minutes, s.active, s.next_run,
                       c.name, c.email, c.package, c.target_url, c.verified
                FROM schedules s
                JOIN companies c ON s.company_id = c.id
                WHERE s.active = 1 AND c.verified = 1
                """
            )
            rows = cur.fetchall()
            for row in rows:
                nr = row["next_run"] or 0
                if nr == 0 or now >= nr:
                    run_tests_for_company(row)
                    next_run = now + 60 * int(row["interval_minutes"])
                    cur.execute("UPDATE schedules SET next_run = ? WHERE id = ?", (next_run, row["id"]))
                    conn.commit()
            conn.close()
            time.sleep(15)
        except Exception as e:
            print(f"[SCHEDULER] Hata: {e}")
            time.sleep(10)


stop_event = threading.Event()
thread = threading.Thread(target=scheduler_loop, args=(stop_event,), daemon=True)


# --------------------------- Auth helpers ---------------------------
def get_current_user():
    uid = session.get("uid")
    if not uid:
        return None
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    u = cur.fetchone()
    conn.close()
    return u


def login_required(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Lütfen giriş yapın", "error")
            return redirect(url_for("login"))
        g.user = user
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Lütfen giriş yapın", "error")
            return redirect(url_for("login"))
        try:
            role = user["role"]
        except Exception:
            role = None
        if role != "admin":
            flash("Bu işlem için yönetici yetkisi gerekli", "error")
            return redirect(url_for("dashboard"))
        g.user = user
        return f(*args, **kwargs)
    return wrapper


# --------------------------- Web UI (templates) ---------------------------
@app.get("/")
def root_redirect():
    # Ana sayfa olarak public landing
    return render_template("landing.html")


@app.get("/login")
def login():
    # Admin giriş sayfasını göster
    return render_template("login.html")


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    u = cur.fetchone()
    conn.close()
    if not u or not check_password_hash(u["password_hash"], password):
        flash("Geçersiz kullanıcı adı veya şifre", "error")
        return redirect(url_for("login"))
    session["uid"] = u["id"]
    return redirect(url_for("dashboard"))

# Admin login form (gerekirse direkt erişim)
@app.get("/admin-login")
def admin_login_view():
    return render_template("login.html")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM companies")
    companies_count = cur.fetchone()["cnt"]
    cur.execute("SELECT COUNT(*) AS cnt FROM schedules WHERE active = 1")
    active_schedules = cur.fetchone()["cnt"]
    cur.execute("SELECT r.id, r.company_id, r.created_at, r.summary, r.detail, c.name FROM results r JOIN companies c ON r.company_id = c.id ORDER BY r.id DESC LIMIT 10")
    recent = cur.fetchall()
    # Risk istatistiği: son 100 sonuçtan severity dağılımı
    try:
        cur.execute("SELECT id, detail FROM results ORDER BY id DESC LIMIT 100")
        stat_rows = cur.fetchall()
    except Exception:
        stat_rows = []
    conn.close()
    critical_findings = sum(1 for r in recent if ('[!]' in r['detail'] or '[-]' in r['detail']))
    activities = [{"title": f"Tarama #{r['id']} tamamlandı", "time": r['created_at'], "meta": f"Şirket #{r['company_id']}"} for r in recent]
    # Severity dağılımını hesapla
    risk_stats = {"high": 0, "medium": 0, "low": 0, "total": 0}
    try:
        for sr in stat_rows:
            items = build_human_explanations(sr["detail"] or "")
            for it in items:
                sev = (it.get("severity") or "").lower()
                if sev.startswith("yüksek"):
                    risk_stats["high"] += 1
                elif sev.startswith("orta"):
                    risk_stats["medium"] += 1
                elif sev.startswith("düşük"):
                    risk_stats["low"] += 1
                risk_stats["total"] += 1
    except Exception:
        pass
    return render_template(
        "dashboard.html",
        companies_count=companies_count,
        active_schedules=active_schedules,
        recent=recent,
        critical_findings=critical_findings,
        activities=activities,
        risk_stats=risk_stats,
    )


@app.get("/results")
@login_required
def results_list():
    company_id = request.args.get("company_id")
    conn = db_connect()
    cur = conn.cursor()
    if company_id:
        try:
            cid = int(company_id)
            cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id WHERE r.company_id = ? ORDER BY r.id DESC LIMIT 100", (cid,))
        except Exception:
            cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id ORDER BY r.id DESC LIMIT 100")
    else:
        cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id ORDER BY r.id DESC LIMIT 100")
    rows = cur.fetchall()
    conn.close()
    explanations = {}
    try:
        for r in rows:
            explanations[r["id"]] = build_human_explanations(r["detail"] or "")
    except Exception:
        explanations = {}
    return render_template("results.html", rows=rows, explanations=explanations)


def _wrap_lines(text: str, width: int = 95) -> list:
    lines = []
    for raw_line in (text or "").splitlines():
        if len(raw_line) <= width:
            lines.append(raw_line)
        else:
            # basit satır sarma
            s = 0
            while s < len(raw_line):
                lines.append(raw_line[s:s+width])
                s += width
    return lines


def build_result_pdf(row: sqlite3.Row, items: list) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    y = height - 40
    # Başlık
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Güvenlik Tarama Raporu")
    y -= 24
    c.setFont("Helvetica", 10)
    company = row.get("name") if hasattr(row, "get") else row["name"]
    summary = row.get("summary") if hasattr(row, "get") else row["summary"]
    created_at = row.get("created_at") if hasattr(row, "get") else row["created_at"]
    # Hedef URL'yi özet metninden ayıkla
    target = ""
    try:
        if summary and "|" in summary:
            parts = [p.strip() for p in summary.split("|")]
            for p in parts:
                if p.lower().startswith("hedef:"):
                    target = p.split(":", 1)[1].strip()
    except Exception:
        target = ""
    c.drawString(40, y, f"Şirket: {company} | Hedef: {target}")
    y -= 16
    c.drawString(40, y, f"Sonuç ID: {row['id']} | Tarih: {created_at}")
    y -= 24

    # Bulgular
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Bulgu ve Öneriler")
    y -= 18
    c.setFont("Helvetica", 10)
    if items:
        for it in items:
            sev = (it.get('severity') or '').lower()
            sev_color = colors.green
            if sev == 'high':
                sev_color = colors.red
            elif sev == 'medium':
                sev_color = colors.orange

            # Severity işareti ve başlık
            c.setFillColor(sev_color)
            c.circle(34, y - 5, 3, fill=1)
            c.setFillColor(colors.black)
            title = f"{it.get('title','')} [{(it.get('severity') or '').capitalize()}]"
            for ln in _wrap_lines(title, 95):
                c.drawString(40, y, "• " + ln)
                y -= 14
                if y < 80:
                    c.showPage(); y = height - 40; c.setFont("Helvetica", 10)
            # Bulgu açıklaması
            expl = it.get('explanation') or ''
            if expl:
                c.setFillColor(colors.HexColor('#555555'))
                for ln in _wrap_lines(expl, 95):
                    c.drawString(40, y, ln)
                    y -= 12
                    if y < 80:
                        c.showPage(); y = height - 40; c.setFont("Helvetica", 10)
            # Öneri
            rec = it.get('recommendation') or ''
            if rec:
                c.setFillColor(colors.HexColor('#777777'))
                for ln in _wrap_lines("Öneri: " + rec, 95):
                    c.drawString(40, y, ln)
                    y -= 12
                    if y < 80:
                        c.showPage(); y = height - 40; c.setFont("Helvetica", 10)
            c.setFillColor(colors.black)
            y -= 6
            if y < 80:
                c.showPage(); y = height - 40; c.setFont("Helvetica", 10)
    else:
        c.drawString(40, y, "Önemli bir risk saptanmadı.")
        y -= 16

    # Ham Ayrıntı
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Ham Ayrıntı")
    y -= 18
    c.setFont("Helvetica", 9)
    for ln in _wrap_lines(row.get('detail') if hasattr(row, 'get') else row['detail'], 95):
        c.drawString(40, y, ln)
        y -= 12
        if y < 60:
            c.showPage(); y = height - 40; c.setFont("Helvetica", 9)

    c.showPage()
    c.save()
    pdf_bytes = buf.getvalue()
    buf.close()
    return pdf_bytes

# --------------------------- JSON Pipeline & Risk Scoring ---------------------------
def compute_risk_score(impact: int, likelihood: int) -> int:
    try:
        i = max(0, min(10, int(impact)))
        l = max(0, min(10, int(likelihood)))
    except Exception:
        i, l = 0, 0
    return i * l  # 0–100 skala

def build_result_json(row: sqlite3.Row) -> Dict[str, Any]:
    try:
        items = build_human_explanations(row["detail"] or "")
    except Exception:
        items = []
    sev_map = {"high": (8, 8), "medium": (5, 5), "low": (2, 2), "bilgi": (1, 1), "yüksek": (8,8), "orta": (5,5)}
    findings = []
    for it in items:
        sev = (it.get('severity') or 'low').lower()
        imp, lik = sev_map.get(sev, (2, 2))
        score = compute_risk_score(imp, lik)
        findings.append({
            "title": it.get('title'),
            "severity": sev,
            "impact": imp,
            "likelihood": lik,
            "score": score,
            "explanation": it.get('explanation'),
            "recommendation": it.get('recommendation'),
            "evidence": it.get('evidence') or {"curl": None, "http_request": None, "http_response": None},
        })
    # Hedef ve profil çıkarımı
    target = ""
    summary = row.get("summary") if hasattr(row, "get") else row["summary"]
    try:
        if summary and "|" in summary:
            parts = [p.strip() for p in summary.split("|")]
            for p in parts:
                if p.lower().startswith("hedef:"):
                    target = p.split(":", 1)[1].strip()
    except Exception:
        target = ""
    detail_txt = row.get("detail") if hasattr(row, "get") else row["detail"]
    profile = "Baseline"
    try:
        txt_low = (detail_txt or "").lower()
        if "agresif" in txt_low:
            profile = "Agresif"
    except Exception:
        pass
    obj: Dict[str, Any] = {
        "result": {
            "id": row["id"],
            "created_at": row["created_at"],
            "company": row["name"],
            "target": target,
            "profile": profile,
        },
        "findings": sorted(findings, key=lambda f: (-f["score"], f["title"]))
    }
    # JSON snapshot persist for pipeline separation
    try:
        conn = db_connect()
        cur = conn.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS result_json_data (result_id INTEGER PRIMARY KEY, data TEXT NOT NULL)"
        )
        cur.execute(
            "INSERT INTO result_json_data (result_id, data) VALUES (?, ?) ON CONFLICT(result_id) DO UPDATE SET data=excluded.data",
            (row["id"], json.dumps(obj, ensure_ascii=False)),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return obj

# --------------------------- Result validation & FP rate ---------------------------
def _confirm_path(base: str, p: str, timeout: float = 4.0) -> Dict[str, Any]:
    url = base + p
    out = {"path": p, "url": url, "status": None, "content_type": None, "confirmed": False, "reason": ""}
    try:
        r = requests.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        out["status"] = r.status_code
        out["content_type"] = (r.headers.get("Content-Type") or "").lower()
        body = r.text or ""
        # Specific confirmation heuristics
        if r.status_code == 200:
            if p == "/.git/HEAD" and ("ref:" in body):
                out["confirmed"] = True; out["reason"] = "Git HEAD ref bulundu"
            elif p == "/.env" and ("SECRET" in body or "KEY=" in body or "DB_" in body):
                out["confirmed"] = True; out["reason"] = ".env içeriği sızıyor"
            elif p in ("/swagger.json", "/api/docs") and ("json" in out["content_type"] or "swagger" in body.lower()):
                out["confirmed"] = True; out["reason"] = "Açık API dokümantasyonu"
            elif p == "/server-status" and ("Server Status" in body or "Apache" in body):
                out["confirmed"] = True; out["reason"] = "Server-status sayfası erişilebilir"
            elif p in ("/backup.zip", "/db.sql", "/dump.sql", "/data.sql", "/backup.tar.gz"):
                out["confirmed"] = True; out["reason"] = "Yedek/DB dosyasına HTTP 200"
            elif p in ("/config.php", "/wp-config.php"):
                out["confirmed"] = True; out["reason"] = "Konfigürasyon dosyasına HTTP 200"
            elif p.endswith("/") and ("Index of" in body):
                out["confirmed"] = True; out["reason"] = "Dizin listeleme aktif"
            else:
                # Genel doğrulama: 200 durum kodu
                out["confirmed"] = True; out["reason"] = "HTTP 200"
        else:
            out["reason"] = f"HTTP {r.status_code}"
    except Exception as e:
        out["reason"] = f"İstek hatası: {e}"
    return out

@app.get("/results/<int:rid>/validate")
@login_required
def validate_result_fp(rid: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT r.id, r.company_id, r.created_at, r.summary, r.detail, c.name, c.target_url FROM results r JOIN companies c ON r.company_id = c.id WHERE r.id = ?", (rid,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "Result not found"}), 404
    # Base URL
    parsed = urlparse(row["target_url"]) if isinstance(row, sqlite3.Row) else urlparse(row.get("target_url"))
    base = f"{parsed.scheme or 'https'}://{parsed.netloc or parsed.path}"
    detail = row["detail"] if isinstance(row, sqlite3.Row) else row.get("detail")
    text = detail or ""
    # Extract candidate paths from raw detail lines
    patterns = [
        r"\[!\]\s*Hassas dosya erişilebilir:\s*(\S+)",
        r"\[!\]\s*API dokümantasyonu herkese açık:\s*(\S+)",
        r"\[!\]\s*Sunucu durum sayfası açık:\s*(\S+)",
        r"\[!\]\s*Yedek/DB dosyası erişilebilir:\s*(\S+)",
        r"\[!\]\s*Konfigürasyon dosyası herkese açık:\s*(\S+)",
        r"\[!\]\s*Dizin listeleme açık:\s*(\S+)",
        r"\[!\]\s*Erişilebilir yol:\s*(\S+)",
    ]
    candidates: List[str] = []
    for pat in patterns:
        for m in re.finditer(pat, text):
            p = m.group(1).strip()
            if p and p not in candidates:
                candidates.append(p)
    # If no explicit paths captured, try PoC lines
    if not candidates:
        for m in re.finditer(r"^PoC:\s*(https?://[^\s]+)$", text, flags=re.MULTILINE):
            full = m.group(1).strip()
            try:
                u = urlparse(full)
                p = full.replace(f"{u.scheme}://{u.netloc}", "")
                if p and p not in candidates:
                    candidates.append(p)
            except Exception:
                pass
    confirmed: List[Dict[str, Any]] = []
    false_pos: List[Dict[str, Any]] = []
    for p in candidates:
        res = _confirm_path(base, p)
        if res["confirmed"]:
            confirmed.append(res)
        else:
            false_pos.append(res)
    prev_count = len(candidates)
    conf_count = len(confirmed)
    fp_count = len(false_pos)
    rate = (fp_count / prev_count) if prev_count > 0 else 0.0
    return jsonify({
        "ok": True,
        "target": base,
        "result_id": row["id"] if isinstance(row, sqlite3.Row) else row.get("id"),
        "previous_path_count": prev_count,
        "confirmed_count": conf_count,
        "false_positive_count": fp_count,
        "false_positive_rate": round(rate, 4),
        "confirmed": confirmed,
        "false_positives": false_pos,
    })


def build_pdf_from_json(obj: Dict[str, Any]) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, height - 40, f"Pentest Raporu - Sonuç #{obj['result']['id']}")
    c.setFont("Helvetica", 10)
    c.drawString(40, height - 56, f"Şirket: {obj['result']['company']} | Hedef: {obj['result']['target']} | Paket: {obj['result']['profile']}")
    y = height - 80
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, "Bulgu ve Öneriler")
    y -= 16
    c.setFont("Helvetica", 10)
    def sev_color(sev: str):
        s = (sev or "low").lower()
        return colors.red if s == "high" else (colors.orange if s == "medium" else colors.green)
    for f in obj.get("findings", []):
        if y < 80:
            c.showPage(); y = height - 40; c.setFont("Helvetica", 10)
        c.setFillColor(sev_color(f.get("severity")))
        c.rect(40, y-2, 6, 12, fill=1, stroke=0)
        c.setFillColor(colors.black)
        c.drawString(52, y+8, f"{f.get('title')} ({(f.get('severity') or '').capitalize()} • Skor {f.get('score')})")
        y -= 12
        c.setFont("Helvetica", 9)
        c.drawString(52, y, f"Bulgu: {f.get('explanation')}")
        y -= 12
        c.drawString(52, y, f"Öneri: {f.get('recommendation')}")
        y -= 16
    c.showPage(); c.save()
    pdf_bytes = buf.getvalue(); buf.close(); return pdf_bytes


@app.get("/results/<int:rid>/pdf")
@login_required
def result_pdf(rid: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id WHERE r.id = ?", (rid,))
    row = cur.fetchone()
    conn.close()
    if not row:
        flash("Sonuç bulunamadı", "error")
        return redirect(url_for("results_list"))
    try:
        items = build_human_explanations(row["detail"] or "")
    except Exception:
        items = []
    # İndirme isteği parametresi
    dl_param = (request.args.get("dl") or "").lower()
    download = dl_param in ("1", "true", "yes")

    if REPORTLAB_AVAILABLE:
        obj = build_result_json(row)
        pdf_bytes = build_pdf_from_json(obj)
        resp = Response(pdf_bytes, mimetype="application/pdf")
        disposition = "attachment" if download else "inline"
        resp.headers["Content-Disposition"] = f"{disposition}; filename=\"result-{rid}.pdf\""
        return resp
    else:
        # Fallback: yazdırılabilir HTML (indirme istenirse HTML olarak indir)
        html = render_template("result_pdf.html", row=row, explanations=items)
        if download:
            resp = Response(html, mimetype="text/html")
            resp.headers["Content-Disposition"] = f"attachment; filename=\"result-{rid}.html\""
            return resp
        return html


@app.get("/results/<int:rid>/json")
@login_required
def result_json(rid: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id WHERE r.id = ?", (rid,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "not_found"}), 404
    # Yedekten oku, yoksa oluştur
    snapshot = None
    try:
        conn = db_connect(); cur = conn.cursor()
        cur.execute("SELECT data FROM result_json_data WHERE result_id = ?", (rid,))
        rj = cur.fetchone()
        if rj:
            snapshot = json.loads(rj[0])
    except Exception:
        snapshot = None
    finally:
        try:
            conn.close()
        except Exception:
            pass
    obj = snapshot or build_result_json(row)
    dl_param = (request.args.get("dl") or "").lower()
    download = dl_param in ("1", "true", "yes")
    payload = json.dumps(obj, ensure_ascii=False, indent=2)
    resp = Response(payload, mimetype="application/json; charset=utf-8")
    disposition = "attachment" if download else "inline"
    resp.headers["Content-Disposition"] = f"{disposition}; filename=\"result-{rid}.json\""
    return resp


@app.get("/results/<int:rid>/view")
@login_required
def results_view(rid: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id WHERE r.id = ?", (rid,))
    row = cur.fetchone()
    if not row:
        flash("Sonuç bulunamadı", "error")
        return redirect(url_for("results_list"))
    try:
        items = build_human_explanations(row["detail"] or "")
    except Exception:
        items = []
    # Özetten hedef URL çıkarımı
    target = ""
    summary = row.get("summary") if hasattr(row, "get") else row["summary"]
    try:
        if summary and "|" in summary:
            parts = [p.strip() for p in summary.split("|")]
            for p in parts:
                if p.lower().startswith("hedef:"):
                    target = p.split(":", 1)[1].strip()
    except Exception:
        target = ""
    # Profil çıkarımı (tahmini)
    detail_txt = row.get("detail") if hasattr(row, "get") else row["detail"]
    profile = "Baseline"
    try:
        txt_low = (detail_txt or "").lower()
        if "agresif" in txt_low:
            profile = "Agresif"
    except Exception:
        pass
    # Çözülen bulguları yükle
    try:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS resolved_findings (id INTEGER PRIMARY KEY, result_id INTEGER NOT NULL, title TEXT NOT NULL, resolved_at INTEGER NOT NULL, UNIQUE(result_id, title))"
        )
        cur.execute("SELECT title FROM resolved_findings WHERE result_id = ?", (rid,))
        resolved_titles = set(t[0] for t in cur.fetchall())
    except Exception:
        resolved_titles = set()
    finally:
        conn.close()
    return render_template("result_view.html", row=row, explanations=items, target=target, profile=profile, resolved_titles=resolved_titles)


@app.post("/results/<int:rid>/resolve")
@login_required
def resolve_finding(rid: int):
    title = (request.json or {}).get("title", "").strip()
    if not title:
        return {"ok": False, "error": "title_required"}, 400
    conn = db_connect()
    cur = conn.cursor()
    try:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS resolved_findings (id INTEGER PRIMARY KEY, result_id INTEGER NOT NULL, title TEXT NOT NULL, resolved_at INTEGER NOT NULL, UNIQUE(result_id, title))"
        )
        cur.execute(
            "INSERT OR IGNORE INTO resolved_findings (result_id, title, resolved_at) VALUES (?, ?, ?)",
            (rid, title, int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.get("/payments")
@login_required
def payments_list():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT p.*, u.username AS user_name, c.name AS company_name
        FROM payments p
        LEFT JOIN users u ON p.user_id = u.id
        LEFT JOIN companies c ON p.company_id = c.id
        ORDER BY p.id DESC LIMIT 100
        """
    )
    rows = cur.fetchall()
    conn.close()
    plan_features = {
        "basic": [
            "Aylık temel güvenlik taraması",
            "HTTP güvenlik başlıkları analizi",
            "Açık port hızlı kontrol (80/443/22 vb.)",
            "Basit HTML yorum/metadata sızıntı kontrolü",
            "Rapor özeti ve öneriler",
        ],
        "pro": [
            "Haftalık kapsamlı tarama",
            "Basic kapsamındaki tüm kontroller",
            "Alt alan (subdomain) keşfi ve HTTP kontrolü",
            "İçerik güvenliği (CSP) ve X-Frame-Options detay analizi",
            "Gelişmiş öneriler ve takip",
        ],
        "enterprise": [
            "Günlük otomatik tarama ve bildirim",
            "Pro kapsamındaki tüm kontroller",
            "Özel kural setleri ve eşik değerleri",
            "Özel entegrasyon (SMTP/Webhook) desteği",
            "Öncelikli destek ve danışmanlık",
        ],
    }
    return render_template("payments.html", rows=rows, plan_features=plan_features)


@app.get("/companies")
@admin_required
def companies_list():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT c.*, 
               (SELECT r.summary FROM results r WHERE r.company_id = c.id ORDER BY r.id DESC LIMIT 1) AS last_summary,
               (SELECT r.detail FROM results r WHERE r.company_id = c.id ORDER BY r.id DESC LIMIT 1) AS last_detail,
               (SELECT r.created_at FROM results r WHERE r.company_id = c.id ORDER BY r.id DESC LIMIT 1) AS last_run
        FROM companies c
        ORDER BY c.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    # Derive a short human-readable hint for last result per company
    hints = {}
    try:
        for c in rows:
            det = c["last_detail"] or ""
            exp = build_human_explanations(det)
            if exp:
                hints[c["id"]] = f"{exp[0]['title']} – {exp[0]['explanation']}"
            else:
                hints[c["id"]] = "Önemli bir sorun görülmedi."
    except Exception:
        hints = {}
    # Aktif doğrulama politikası
    try:
        sc = db_connect()
        sccur = sc.cursor()
        sccur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
        st = sccur.fetchone()
        sc.close()
        policy = st["verification_policy"] if st and "verification_policy" in st.keys() else "standard"
    except Exception:
        policy = "standard"
    return render_template("companies.html", rows=rows, hints=hints, verification_policy=policy)


@app.get("/companies/new")
@admin_required
def companies_new():
    return render_template("company_form.html", company=None)


@app.post("/companies/create")
@admin_required
def companies_create():
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    package = (request.form.get("package") or "basic").strip()
    target_url = normalize_url(request.form.get("target_url"))
    aggressive = 1 if (request.form.get("aggressive_pentest") == "on") else 0
    if not name or not target_url:
        flash("Şirket adı ve hedef URL gerekli", "error")
        return redirect(url_for("companies_new"))
    conn = db_connect()
    cur = conn.cursor()
    # Admin tarafından eklenen şirketler varsayılan olarak doğrulanmış kabul edilir
    cur.execute("INSERT INTO companies(name,email,package,target_url,verified,aggressive_pentest) VALUES (?,?,?,?,1,?)", (name, email, package, target_url, aggressive))
    company_id = cur.lastrowid
    conn.commit()
    # Oluşturma sonrası ilk taramayı otomatik çalıştır
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    conn.close()
    try:
        run_tests_for_company(c)
        flash("Şirket eklendi ve ilk tarama başlatıldı", "success")
    except Exception as e:
        flash(f"Şirket eklendi ancak tarama hata verdi: {e}", "error")
    return redirect(url_for("companies_list"))


@app.get("/companies/<int:company_id>/edit")
@admin_required
def companies_edit(company_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    conn.close()
    if not c:
        flash("Şirket bulunamadı", "error")
        return redirect(url_for("companies_list"))
    return render_template("company_form.html", company=c)


@app.post("/companies/<int:company_id>/update")
@admin_required
def companies_update(company_id: int):
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    package = (request.form.get("package") or "basic").strip()
    target_url = normalize_url(request.form.get("target_url"))
    aggressive = 1 if (request.form.get("aggressive_pentest") == "on") else 0
    if not name or not target_url:
        flash("Şirket adı ve hedef URL gerekli", "error")
        return redirect(url_for("companies_edit", company_id=company_id))
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("UPDATE companies SET name=?, email=?, package=?, target_url=?, aggressive_pentest=? WHERE id=?", (name, email, package, target_url, aggressive, company_id))
    conn.commit()
    conn.close()
    flash("Şirket güncellendi", "success")
    return redirect(url_for("companies_list"))


@app.post("/companies/<int:company_id>/verify-check")
@admin_required
def companies_verify_check(company_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    if not c:
        conn.close()
        flash("Şirket bulunamadı", "error")
        return redirect(url_for("companies_list"))
    # Ayarlardan politika al
    try:
        sc = db_connect()
        sccur = sc.cursor()
        sccur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
        st = sccur.fetchone()
        sc.close()
        policy = st["verification_policy"] if st and "verification_policy" in st.keys() else "standard"
    except Exception:
        policy = "standard"
    # Token ve doğrulama yöntemi mevcut mu?
    token = (c["verify_token"] if "verify_token" in c.keys() else None)
    method = (c["verify_method"] if "verify_method" in c.keys() else "http_file")
    if not token:
        conn.close()
        flash("Doğrulama token'ı bulunamadı.", "error")
        return redirect(url_for("companies_list"))
    # Hedef alan adı ve şema
    try:
        parsed = urlparse(c["target_url"])  # type: ignore
        scheme = parsed.scheme or "https"
        host = parsed.netloc or parsed.path
        verify_url = f"{scheme}://{host}/.well-known/pentest-verify.txt"
    except Exception:
        conn.close()
        flash("Geçersiz hedef URL.", "error")
        return redirect(url_for("companies_list"))
    # HTTP dosya ile doğrulama
    http_ok = False
    try:
        resp = requests.get(verify_url, headers=DEFAULT_HEADERS, timeout=5)
        content = (resp.text or "").strip()
        ctype = (resp.headers.get('Content-Type') or '').lower()
        http_ok = (resp.status_code == 200 and content == token and ctype.startswith('text/plain'))
    except Exception:
        http_ok = False

    # DNS TXT doğrulama
    dns_ok = dns_txt_has_token(host, token)

    if method in ("http_file", "http_and_dns", "dns_txt"):
        try:
            # Politika kontrolü
            ok = False
            if policy == "http_and_dns":
                ok = http_ok and dns_ok
            elif policy == "standard":
                ok = http_ok or dns_ok
            elif policy == "http_only":
                ok = http_ok
            elif policy == "dns_only":
                ok = dns_ok
            else:
                ok = False

            if ok:
                cur.execute("UPDATE companies SET verified = 1 WHERE id = ?", (company_id,))
                conn.commit()
                conn.close()
                flash(f"Doğrulama başarılı. (HTTP={http_ok}, DNS={dns_ok})", "success")
            else:
                conn.close()
                fail_reasons = []
                if policy in ("http_and_dns", "standard", "http_only") and not http_ok:
                    fail_reasons.append("HTTP dosya")
                if policy in ("http_and_dns", "standard", "dns_only") and not dns_ok:
                    fail_reasons.append("DNS TXT")
                flash("Doğrulama başarısız: " + ", ".join(fail_reasons) + f" kontrolü geçmedi. (HTTP={http_ok}, DNS={dns_ok})", "error")
        except Exception as e:
            conn.close()
            flash(f"Doğrulama hata verdi: {e}", "error")
    return redirect(url_for("companies_list"))


@app.get("/verify-email")
def email_verify():
    try:
        company_id = int(request.args.get("company_id") or 0)
        token = (request.args.get("token") or "").strip()
    except Exception:
        flash("Geçersiz istek.", "error")
        return redirect(url_for("login"))
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    if not c:
        conn.close()
        flash("Şirket bulunamadı.", "error")
        return redirect(url_for("login"))
    # Ayarlardan politika
    sc = db_connect()
    sccur = sc.cursor()
    sccur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
    st = sccur.fetchone()
    sc.close()
    policy = st["verification_policy"] if st and "verification_policy" in st.keys() else "http_and_dns"
    # Yalnızca email_link politikasında geçerli
    if policy != "email_link":
        conn.close()
        flash("E-posta link doğrulaması devre dışı.", "error")
        return redirect(url_for("login"))
    # Token kontrolü ve e-posta alan eşleşmesi
    try:
        host = get_host_from_url(c["target_url"])  # type: ignore
        edom = email_domain(c["email"])  # type: ignore
        if (c["email_verify_token"] == token) and domains_match(edom, host):
            cur.execute("UPDATE companies SET verified = 1 WHERE id = ?", (company_id,))
            conn.commit()
            conn.close()
            flash("E-posta doğrulaması başarılı. Tarama etkinleştirildi.", "success")
            return redirect(url_for("login"))
        else:
            conn.close()
            flash("E-posta doğrulaması başarısız.", "error")
            return redirect(url_for("login"))
    except Exception:
        conn.close()
        flash("Doğrulama hata verdi.", "error")
        return redirect(url_for("login"))


@app.get("/schedules")
@login_required
def schedules_list():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT s.*, c.name FROM schedules s JOIN companies c ON s.company_id = c.id ORDER BY s.id DESC")
    rows = cur.fetchall()
    conn.close()
    return render_template("schedules.html", rows=rows)


@app.get("/schedules/new")
@login_required
def schedules_new():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM companies ORDER BY id DESC")
    companies = cur.fetchall()
    conn.close()
    return render_template("schedule_form.html", companies=companies)


@app.post("/schedules/create")
@login_required
def schedules_create():
    try:
        company_id = int(request.form.get("company_id"))
        interval_minutes = int(request.form.get("interval_minutes"))
    except Exception:
        flash("Geçersiz ID veya aralık", "error")
        return redirect(url_for("schedules_new"))
    conn = db_connect()
    cur = conn.cursor()
    next_run = int(time.time()) + 60 * interval_minutes
    cur.execute("INSERT INTO schedules(company_id, interval_minutes, active, next_run) VALUES (?,?,1,?)", (company_id, interval_minutes, next_run))
    conn.commit()
    conn.close()
    flash("Program eklendi", "success")
    return redirect(url_for("schedules_list"))


@app.post("/schedules/<int:schedule_id>/toggle")
@login_required
def schedules_toggle(schedule_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,))
    s = cur.fetchone()
    if not s:
        conn.close()
        flash("Program bulunamadı", "error")
        return redirect(url_for("schedules_list"))
    new_active = 0 if s["active"] else 1
    next_run = s["next_run"]
    # Aktif yapılıyorsa bir sonraki çalışmayı şimdi + interval ile ayarla
    if new_active == 1:
        next_run = int(time.time()) + 60 * int(s["interval_minutes"])
    cur.execute("UPDATE schedules SET active = ?, next_run = ? WHERE id = ?", (new_active, next_run, schedule_id))
    conn.commit()
    conn.close()
    flash("Program güncellendi", "success")
    return redirect(url_for("schedules_list"))


@app.post("/run-now")
@login_required
def run_now():
    try:
        company_id = int(request.form.get("company_id"))
    except Exception:
        flash("Geçersiz şirket ID", "error")
        return redirect(url_for("dashboard"))
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    conn.close()
    if not c:
        flash("Şirket bulunamadı", "error")
        return redirect(url_for("dashboard"))
    # Doğrulanmamış şirketlerde manuel tarama engellenir
    if ("verified" in c.keys()) and (int(c["verified"]) != 1):
        flash("Bu şirket doğrulanmadı. Tarama başlatmadan önce doğrulayın.", "error")
        return redirect(url_for("companies_list"))
    run_tests_for_company(c)
    flash("Manuel tarama çalıştırıldı", "success")
    return redirect(url_for("results_list", company_id=company_id))


@app.get("/settings")
@login_required
def settings_view():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
    st = cur.fetchone()
    conn.close()
    policies = [
        ("http_and_dns", "Strict (HTTP dosya + DNS TXT birlikte şart)"),
        ("standard", "Standard (HTTP dosya veya DNS TXT yeterli)"),
        ("http_only", "HTTP dosya doğrulaması yeterli"),
        ("dns_only", "DNS TXT doğrulaması yeterli"),
        ("email_link", "Alan eşleşen e-postaya gönderilen link ile doğrulama"),
    ]
    return render_template("settings.html", st=st, policies=policies)


# --------------------------- Local Auth Test (using JSON config) ---------------------------
@app.get("/auth-local")
def auth_local_report():
    """Run a minimal authenticated check against a local dev server using local_security_test_config.json.
    Returns text output with PoC lines for quick verification. This does NOT persist to DB.
    """
    try:
        cfg_path = os.path.join(os.path.dirname(__file__), "local_security_test_config.json")
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        return Response(f"[!] Konfigürasyon okunamadı: {e}", mimetype="text/plain")

    base = cfg.get("target_base_url", "http://127.0.0.1:5013").rstrip("/")
    login_endpoint = cfg.get("login_endpoint", "/api/login")
    payload = cfg.get("login_payload_example", {})
    cookie_name = cfg.get("session_cookie_name", "session")
    endpoints = cfg.get("protected_endpoints", [])

    lines = ["[*] Yerel Auth Test", f"[i] Base: {base}"]
    sess = requests.Session()
    try:
        r = sess.post(base + login_endpoint, json=payload, headers=DEFAULT_HEADERS, timeout=4, allow_redirects=True)
        if r.status_code == 200 or r.status_code == 204:
            lines.append("[i] Login denemesi: HTTP OK")
        else:
            lines.append(f"[-] Login başarısız: HTTP {r.status_code}")
        lines.append(f"PoC: {base}{login_endpoint}")
    except Exception as e:
        lines.append(f"[!] Login isteği hata: {e}")
        lines.append(f"PoC: {base}{login_endpoint}")

    # Cookie mevcut mu?
    try:
        has_cookie = (cookie_name in sess.cookies.keys())
    except Exception:
        has_cookie = False
    if has_cookie:
        lines.append(f"[i] Session cookie alındı: {cookie_name}")
    else:
        lines.append(f"[i] Session cookie bulunamadı: {cookie_name}")

    # Korunan uçlar
    for ep in endpoints:
        method = (ep.get("method") or "GET").upper()
        path = ep.get("path") or "/"
        url = base + path
        try:
            if method == "GET":
                rr = sess.get(url, headers=DEFAULT_HEADERS, timeout=4, allow_redirects=True)
            elif method == "POST":
                rr = sess.post(url, headers=DEFAULT_HEADERS, timeout=4, allow_redirects=True)
            elif method == "HEAD":
                rr = sess.head(url, headers=DEFAULT_HEADERS, timeout=4, allow_redirects=True)
            else:
                rr = sess.request(method, url, headers=DEFAULT_HEADERS, timeout=4, allow_redirects=True)
            sc = rr.status_code
            if sc == 200:
                lines.append(f"[i] Erişim OK: {path} (HTTP 200)")
            elif sc in (401, 403):
                lines.append(f"[!] Yetki gerekli: {path} (HTTP {sc})")
            else:
                lines.append(f"[i] {path}: HTTP {sc}")
            lines.append(f"PoC: {url}")
        except Exception as e:
            lines.append(f"[!] İstek hata: {path} :: {e}")
            lines.append(f"PoC: {url}")

    return Response("\n".join(lines), mimetype="text/plain")


@app.post("/settings/save")
@login_required
def settings_save():
    data = {
        "smtp_host": (request.form.get("smtp_host") or "").strip(),
        "smtp_port": int(request.form.get("smtp_port") or 587),
        "smtp_user": (request.form.get("smtp_user") or "").strip(),
        "smtp_pass": (request.form.get("smtp_pass") or "").strip(),
        "smtp_tls": 1 if (request.form.get("smtp_tls") == "on") else 0,
        "webhook_url": (request.form.get("webhook_url") or "").strip(),
        "verification_policy": (request.form.get("verification_policy") or "standard").strip(),
    }
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO settings(smtp_host,smtp_port,smtp_user,smtp_pass,smtp_tls,webhook_url,verification_policy) VALUES (?,?,?,?,?,?,?)",
                (data["smtp_host"], data["smtp_port"], data["smtp_user"], data["smtp_pass"], data["smtp_tls"], data["webhook_url"], data["verification_policy"]))
    conn.commit()
    conn.close()
    flash("Ayarlar kaydedildi", "success")
    return redirect(url_for("settings_view"))

# --------------------------- Public order page ---------------------------
@app.get("/order")
def public_order_view():
    plans = ["basic", "pro", "enterprise"]
    # Geçerli politika bilgisi
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
    st = cur.fetchone()
    conn.close()
    policy = st["verification_policy"] if st and "verification_policy" in st.keys() else "standard"
    return render_template("order.html", plans=plans, verification_policy=policy)

# --------------------------- Public landing (tanıtım) ---------------------------
@app.get("/public")
def public_landing_view():
    return render_template("landing.html")

# Çoklu sayfa: public özellikler, hakkında ve iletişim
@app.get("/features")
@app.get("/features/")
def features_public_view():
    base_html = render_template("layout.html", title="Test")
    html = render_template("features_public.html", title="Özellikler")
    print(f"[DEBUG] layout.html length: {len(base_html)}; features_public.html length: {len(html)}")
    return html

@app.get("/about")
@app.get("/about/")
def about_public_view():
    html = render_template("about_public.html", title="Hakkımızda")
    print(f"[DEBUG] about_public.html length: {len(html)}")
    return html

@app.get("/contact")
@app.get("/contact/")
def contact_public_view():
    html = render_template("contact_public.html", title="İletişim")
    print(f"[DEBUG] contact_public.html length: {len(html)}")
    return html

# --------------------------- Debug: Jinja template loader/render ---------------------------
@app.get("/_debug_tpl/<path:name>")
def debug_template_source(name: str):
    try:
        src, filename, uptodate = app.jinja_loader.get_source(app.jinja_env, name)
        head = src[:200].replace("\n", "\\n")
        try:
            up = uptodate()
        except Exception:
            up = 'unknown'
        return f"name={name}\nfile={filename}\nlen={len(src)}\nuptodate={up}\nhead={head}"
    except Exception as e:
        return f"error: {e}", 500

@app.get("/_debug_render/<path:name>")
def debug_template_render(name: str):
    try:
        tpl = app.jinja_env.get_template(name)
        s = tpl.render(title="Debug")
        head = s[:200].replace("\n", "\\n")
        print(f"[DEBUG] _debug_render {name} length: {len(s)}")
        return f"name={name}\nlen={len(s)}\nhead={head}"
    except Exception as e:
        return f"error: {e}", 500

@app.get("/_debug_render_from_string/<path:name>")
def debug_render_from_string(name: str):
    try:
        import os
        import jinja2
        # Dosya içeriğini oku
        base_dir = os.path.dirname(__file__)
        file_path = os.path.join(base_dir, 'templates', name)
        with open(file_path, 'r', encoding='utf-8') as f:
            src = f.read()

        # Jinja cache temizle ve loader ile render dene
        try:
            app.jinja_env.cache.clear()
        except Exception:
            pass
        s_loader = app.jinja_env.get_template(name).render(title="Debug")

        # Yeni environment ile from_string render dene (extends çözebilsin diye aynı loader ile)
        # Flask'ın mevcut Jinja envsini kullanarak from_string (url_for ve diğer globals mevcut)
        from flask import url_for as flask_url_for
        s_string = app.jinja_env.from_string(src).render(title="Debug", url_for=flask_url_for)

        head_loader = (s_loader[:200] or '').replace("\n", "\\n")
        head_string = (s_string[:200] or '').replace("\n", "\\n")
        return (
            f"name={name}\nsrc_len={len(src)}\nloader_len={len(s_loader)}\nstring_len={len(s_string)}"
            f"\nhead_loader={head_loader}\nhead_string={head_string}"
        )
    except Exception as e:
        return f"error: {e}", 500


@app.post("/order")
def public_order_submit():
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip()
    target_url = normalize_url(request.form.get("target_url") or "")
    plan = (request.form.get("plan") or "basic").strip()
    if plan not in ("basic","pro","enterprise"):
        plan = "basic"
    if not name or not target_url or not email:
        flash("Lütfen şirket adı, e-posta ve hedef URL alanlarını doldurun.", "error")
        return redirect(url_for("public_order_view"))
    # Basit rate limit: IP başına saatlik 3 başvuru
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
    now = int(time.time())
    bucket = ORDER_RATE.get(ip, [])
    bucket = [t for t in bucket if now - t < 3600]
    if len(bucket) >= 3:
        flash("Çok fazla talep. Lütfen daha sonra tekrar deneyin.", "error")
        return redirect(url_for("public_order_view"))
    bucket.append(now)
    ORDER_RATE[ip] = bucket

    # E-posta alanı hedef alan ile eşleşmeli
    host = get_host_from_url(target_url)
    edom = email_domain(email)
    if not domains_match(edom, host):
        flash("E-posta alanı hedef alan ile eşleşmiyor.", "error")
        return redirect(url_for("public_order_view"))
    # Aktif politika
    try:
        pc_conn = db_connect()
        pc_cur = pc_conn.cursor()
        pc_cur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
        st = pc_cur.fetchone()
        pc_conn.close()
        policy = st["verification_policy"] if st and "verification_policy" in st.keys() else "http_and_dns"
    except Exception:
        policy = "http_and_dns"
    # Alan sahipliği doğrulama için token üret
    token = os.urandom(16).hex()
    method = 'http_and_dns'
    conn = db_connect()
    cur = conn.cursor()
    # Public talepler doğrulanana kadar tarama başlatılmaz
    if policy == 'email_link':
        email_token = os.urandom(20).hex()
        method = 'email_link'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method, email_verify_token) VALUES (?,?,?,?,0,?,?,?)",
            (name, email, plan, target_url, token, method, email_token)
        )
    elif policy == 'http_only':
        method = 'http_file'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method) VALUES (?,?,?,?,0,?,?)",
            (name, email, plan, target_url, token, method)
        )
    elif policy == 'dns_only':
        method = 'dns_txt'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method) VALUES (?,?,?,?,0,?,?)",
            (name, email, plan, target_url, token, method)
        )
    elif policy == 'standard':
        method = 'http_and_dns'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method) VALUES (?,?,?,?,0,?,?)",
            (name, email, plan, target_url, token, method)
        )
    else:
        method = 'http_and_dns'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method) VALUES (?,?,?,?,0,?,?)",
            (name, email, plan, target_url, token, method)
        )
    company_id = cur.lastrowid
    conn.commit()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    company = cur.fetchone()
    conn.close()
    # Doğrulama talimatlarını e-posta ile gönder
    try:
        parsed = urlparse(target_url)
        scheme = parsed.scheme or "https"
        host = parsed.netloc or parsed.path
        verify_url = f"{scheme}://{host}/.well-known/pentest-verify.txt"
        if policy == 'email_link':
            link = f"{request.url_root.rstrip('/')}{url_for('email_verify')}?company_id={company_id}&token={company['email_verify_token']}"
            body = (
                "Test talebiniz alındı. Devam etmek için aşağıdaki doğrulama linkine tıklayın.\n\n"
                f"Alan eşleşen e-posta doğrulaması: {link}\n\n"
                "Link çalışmıyorsa bizimle iletişime geçin."
            )
        elif policy == 'http_only':
            body = (
                "Test talebiniz alındı. Devam edebilmek için alan sahipliğini doğrulayın.\n\n"
                f"HTTP dosya doğrulaması: {verify_url} konumunda içeriği SADECE şu token olan dosyayı yayınlayın:\n{token}\n"
            )
        elif policy == 'dns_only':
            body = (
                "Test talebiniz alındı. Devam edebilmek için alan sahipliğini doğrulayın.\n\n"
                f"DNS TXT doğrulaması: {host} için TXT kaydına şu değeri ekleyin:\n{token}\n"
            )
        elif policy == 'standard':
            body = (
                "Test talebiniz alındı. Devam edebilmek için alan sahipliğini doğrulayın.\n\n"
                f"HTTP dosya doğrulaması: {verify_url} konumunda içeriği SADECE şu token olan dosyayı yayınlayın:\n{token}\n\n"
                f"VEYA DNS TXT doğrulaması: {host} için TXT kaydına şu değeri ekleyin:\n{token}\n"
            )
        else:
            body = (
                "Test talebiniz alındı. Devam edebilmek için alan sahipliğini doğrulayın.\n\n"
                f"1) HTTP dosya doğrulaması: {verify_url} konumunda içeriği SADECE şu token olan dosyayı yayınlayın:\n{token}\n\n"
                f"2) DNS TXT doğrulaması: {host} için TXT kaydına şu değeri ekleyin:\n{token}\n\n"
                "Her iki doğrulama başarılı olduktan sonra sistem taramayı etkinleştirmenize izin verecektir."
            )
        notify(email, "Alan Doğrulama Talimatları", body)
    except Exception as e:
        print(f"[ORDER] Notify error: {e}")

    flash("Talebiniz alındı. Lütfen e-posta ile gönderilen talimatlara göre doğrulama yapın.", "success")
    return redirect(url_for("login"))

# --------------------------- Payments & Pricing ---------------------------
try:
    import stripe  # type: ignore
except Exception:
    stripe = None

PRICES_TRY = {
    "basic": 9900,
    "pro": 19900,
    "enterprise": 49900,
}


@app.get("/pricing")
@login_required
def pricing_view():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name, package FROM companies ORDER BY id DESC")
    companies = cur.fetchall()
    conn.close()
    pub_key = os.environ.get("STRIPE_PUBLIC_KEY")
    plan_features = {
        "basic": [
            "Aylık temel güvenlik taraması",
            "HTTP güvenlik başlıkları analizi",
            "Açık port hızlı kontrol (80/443/22 vb.)",
            "Basit HTML yorum/metadata sızıntı kontrolü",
            "Rapor özeti ve öneriler",
        ],
        "pro": [
            "Haftalık kapsamlı tarama",
            "Basic kapsamındaki tüm kontroller",
            "Alt alan (subdomain) keşfi ve HTTP kontrolü",
            "İçerik güvenliği (CSP) ve X-Frame-Options detay analizi",
            "Gelişmiş öneriler ve takip",
        ],
        "enterprise": [
            "Günlük otomatik tarama ve bildirim",
            "Pro kapsamındaki tüm kontroller",
            "Özel kural setleri ve eşik değerleri",
            "Özel entegrasyon (SMTP/Webhook) desteği",
            "Öncelikli destek ve danışmanlık",
        ],
    }
    # Planlara göre yapılan testlerin karşılaştırma matrisi
    plan_tests = [
        {"name": "HTTP Güvenlik Başlıkları", "basic": True, "pro": True, "enterprise": True},
        {"name": "CSP / X-Frame-Options Analizi", "basic": False, "pro": True, "enterprise": True},
        {"name": "Açık Port Kontrolü (80/443/22)", "basic": True, "pro": True, "enterprise": True},
        {"name": "Geniş Port Taraması (top 1000)", "basic": False, "pro": True, "enterprise": True},
        {"name": "Temel Sızma Testleri (güvenli)", "basic": False, "pro": True, "enterprise": True},
        {"name": "Alt Alan (Subdomain) Keşfi", "basic": False, "pro": True, "enterprise": True},
        {"name": "HTML Yorum/Metadata Sızıntı Kontrolü", "basic": True, "pro": True, "enterprise": True},
        {"name": "DNS/HTTP Doğrulama Takibi", "basic": True, "pro": True, "enterprise": True},
        {"name": "Otomatik Tarama Sıklığı", "basic": "Aylık", "pro": "Haftalık", "enterprise": "Günlük"},
        {"name": "Bildirim Entegrasyonları (SMTP/Webhook)", "basic": False, "pro": False, "enterprise": True},
        {"name": "Özel Kural ve Eşikler", "basic": False, "pro": False, "enterprise": True},
    ]
    return render_template(
        "pricing.html",
        companies=companies,
        prices=PRICES_TRY,
        stripe_public_key=pub_key,
        plan_features=plan_features,
        plan_tests=plan_tests,
    )


@app.post("/checkout")
@login_required
def checkout():
    company_id = int(request.form.get("company_id") or 0)
    plan = (request.form.get("plan") or "basic").strip()
    if plan not in PRICES_TRY:
        flash("Geçersiz plan", "error")
        return redirect(url_for("pricing_view"))
    amount = PRICES_TRY[plan]
    currency = "try"

    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO payments(user_id, company_id, plan, amount, currency, status, provider, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (g.user["id"], company_id, plan, amount, currency, "initiated", "stripe" if stripe else "offline", int(time.time())),
    )
    payment_id = cur.lastrowid
    conn.commit()

    secret = os.environ.get("STRIPE_SECRET_KEY")
    if stripe and secret:
        try:
            stripe.api_key = secret
            session_obj = stripe.checkout.Session.create(
                mode="payment",
                payment_method_types=["card"],
                line_items=[{
                    "price_data": {
                        "currency": currency,
                        "product_data": {"name": f"PenTest SaaS: {plan.title()}"},
                        "unit_amount": amount,
                    },
                    "quantity": 1,
                }],
                success_url=url_for("pay_success", payment_id=payment_id, _external=True),
                cancel_url=url_for("pay_cancel", payment_id=payment_id, _external=True),
            )
            cur.execute("UPDATE payments SET provider_session_id=? WHERE id=?", (session_obj.id, payment_id))
            conn.commit()
            conn.close()
            return redirect(session_obj.url)
        except Exception as e:
            flash(f"Stripe hatası: {e}", "error")

    # Offline fallback
    try:
        cur.execute("UPDATE payments SET status=?, receipt_url=? WHERE id=?", ("paid", "#", payment_id))
        cur.execute("UPDATE companies SET package=? WHERE id=?", (plan, company_id))
        conn.commit()
        conn.close()
        flash("Ödeme simüle edildi ve paket güncellendi.", "success")
        return redirect(url_for("dashboard"))
    except Exception as e:
        conn.close()
        flash(f"Ödeme güncelleme hatası: {e}", "error")
        return redirect(url_for("pricing_view"))


@app.get("/pay/success")
@login_required
def pay_success():
    payment_id = int(request.args.get("payment_id") or 0)
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM payments WHERE id=?", (payment_id,))
    p = cur.fetchone()
    if not p:
        conn.close()
        flash("Ödeme bulunamadı", "error")
        return redirect(url_for("pricing_view"))
    try:
        cur.execute("UPDATE payments SET status=? WHERE id=?", ("paid", payment_id))
        if p["company_id"] and p["plan"]:
            cur.execute("UPDATE companies SET package=? WHERE id=?", (p["plan"], p["company_id"]))
        conn.commit()
    finally:
        conn.close()
    flash("Ödeme tamamlandı ve paket güncellendi.", "success")
    return redirect(url_for("dashboard"))


@app.get("/pay/cancel")
@login_required
def pay_cancel():
    payment_id = int(request.args.get("payment_id") or 0)
    conn = db_connect()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE payments SET status=? WHERE id=?", ("failed", payment_id))
        conn.commit()
    finally:
        conn.close()
    flash("Ödeme iptal edildi.", "error")
    return redirect(url_for("pricing_view"))


def create_default_company_if_empty():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM companies")
    cnt = cur.fetchone()["cnt"]
    if cnt == 0:
        cur.execute("INSERT INTO companies(name,email,package,target_url,verified) VALUES (?,?,?,?,1)",
                    ("Örnek Şirket", "security@example.com", "pro", "https://example.com"))
        conn.commit()
    conn.close()


def create_default_admin_if_empty():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS cnt FROM users")
    cnt = cur.fetchone()["cnt"]
    if cnt == 0:
        cur.execute("INSERT INTO users(username, password_hash, role) VALUES (?,?,?)",
                    ("admin", generate_password_hash("admin123", method='pbkdf2:sha256'), "admin"))
        conn.commit()
    conn.close()


# Herkese açık planlar sayfası (sadece tanıtım, işlem yok)
@app.get("/plans")
def plans_public_view():
    plan_features = {
        "basic": [
            "Aylık temel güvenlik taraması",
            "HTTP güvenlik başlıkları analizi",
            "Rapor özeti ve öneriler",
        ],
        "pro": [
            "Haftalık kapsamlı tarama",
            "Alt alan keşfi ve ek analizler",
            "Gelişmiş öneriler ve takip",
        ],
        "enterprise": [
            "Günlük otomatik tarama",
            "Özel kural setleri ve entegrasyonlar",
            "Öncelikli destek",
        ],
    }
    prices = {
        "basic": PRICES_TRY.get("basic"),
        "pro": PRICES_TRY.get("pro"),
        "enterprise": PRICES_TRY.get("enterprise"),
    }
    return render_template("plans_public.html", plan_features=plan_features, prices=prices)

# --------------------------- Admin Plans ---------------------------
@app.get("/admin/plans")
@admin_required
def admin_plans_view():
    # Admin paneli için basit plan listesi; ileride yönetim aksiyonları eklenebilir
    plans = ["basic", "pro", "enterprise"]
    return render_template("plans_admin.html", plans=plans)


# --------------------------- React API & CORS ---------------------------
def row_to_dict(row):
    try:
        return {k: row[k] for k in row.keys()}
    except Exception:
        try:
            return dict(row)
        except Exception:
            return {}

def rows_to_list(rows):
    return [row_to_dict(r) for r in (rows or [])]

FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:5173")

@app.after_request
def add_cors_headers(resp):
    try:
        origin = request.headers.get("Origin")
        allow = FRONTEND_ORIGIN
        if allow == "*":
            if origin:
                resp.headers["Access-Control-Allow-Origin"] = origin
        elif origin and origin == allow:
            resp.headers["Access-Control-Allow-Origin"] = allow
        if resp.headers.get("Access-Control-Allow-Origin"):
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    except Exception:
        pass
    return resp

@app.route("/api/_options", methods=["OPTIONS"])
def api_options():
    return ("", 204)


# --------------------------- Auth (API) ---------------------------
@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    u = cur.fetchone()
    conn.close()
    if not u or not check_password_hash(u["password_hash"], password):
        return jsonify({"ok": False, "error": "invalid_credentials"}), 401
    session["uid"] = u["id"]
    role = u["role"] if ("role" in u.keys()) else None
    return jsonify({"ok": True, "user": {"id": u["id"], "username": u["username"], "role": role}})

@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/me")
def api_me():
    u = get_current_user()
    if not u:
        return jsonify({"ok": False}), 401
    role = u["role"] if ("role" in u.keys()) else None
    return jsonify({"ok": True, "user": {"id": u["id"], "username": u["username"], "role": role}})


# --------------------------- Companies (API) ---------------------------
@app.get("/api/companies")
@login_required
def api_companies_list():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT c.*, 
               (SELECT r.detail FROM results r WHERE r.company_id=c.id ORDER BY r.id DESC LIMIT 1) AS last_detail,
               (SELECT r.summary FROM results r WHERE r.company_id=c.id ORDER BY r.id DESC LIMIT 1) AS last_summary,
               (SELECT r.created_at FROM results r WHERE r.company_id=c.id ORDER BY r.id DESC LIMIT 1) AS last_run
        FROM companies c
        ORDER BY c.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return jsonify({"ok": True, "companies": rows_to_list(rows)})

@app.get("/api/companies/<int:company_id>")
@login_required
def api_companies_get(company_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    conn.close()
    if not c:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "company": row_to_dict(c)})

@app.post("/api/companies")
@login_required
def api_companies_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    package = (data.get("package") or "basic").strip()
    target_url = normalize_url(data.get("target_url") or "")
    if not name or not target_url:
        return jsonify({"ok": False, "error": "validation"}), 400
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO companies(name,email,package,target_url,verified) VALUES (?,?,?,?,0)",
        (name, email, package, target_url)
    )
    cid = cur.lastrowid
    conn.commit()
    cur.execute("SELECT * FROM companies WHERE id = ?", (cid,))
    c = cur.fetchone()
    conn.close()
    return jsonify({"ok": True, "company": row_to_dict(c)})

@app.put("/api/companies/<int:company_id>")
@login_required
def api_companies_update(company_id: int):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    package = (data.get("package") or "basic").strip()
    target_url = normalize_url(data.get("target_url") or "")
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("UPDATE companies SET name=?, email=?, package=?, target_url=? WHERE id=?",
                (name, email, package, target_url, company_id))
    conn.commit()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    conn.close()
    if not c:
        return jsonify({"ok": False, "error": "not_found"}), 404
    return jsonify({"ok": True, "company": row_to_dict(c)})

@app.post("/api/companies/<int:company_id>/verify-check")
@login_required
def api_companies_verify_check(company_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    if not c:
        conn.close()
        return jsonify({"ok": False, "error": "not_found"}), 404
    cur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
    st = cur.fetchone()
    policy = st["verification_policy"] if st and "verification_policy" in st.keys() else "http_and_dns"
    token = c["verify_token"]
    parsed = urlparse(c["target_url"] or "")
    scheme = parsed.scheme or "https"
    host = parsed.netloc or parsed.path
    verify_url = f"{scheme}://{host}/.well-known/pentest-verify.txt"
    ok = False
    try:
        if c.get("verify_method") == "http_file" or policy in ("http_only", "standard", "http_and_dns"):
            try:
                r = requests.get(verify_url, headers=DEFAULT_HEADERS, timeout=4.0)
                body = (r.text or "").strip()
                if r.status_code == 200 and token and body == token:
                    ok = True
            except Exception:
                pass
        if not ok and (c.get("verify_method") == "dns_txt" or policy in ("dns_only", "standard", "http_and_dns")):
            try:
                ok = dns_txt_has_token(host, token)
            except Exception:
                ok = False
    except Exception:
        ok = False
    if ok:
        try:
            cur.execute("UPDATE companies SET verified=1 WHERE id=?", (company_id,))
            conn.commit()
        except Exception:
            pass
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c2 = cur.fetchone()
    conn.close()
    return jsonify({"ok": True, "verified": bool(c2["verified"]) if c2 else False})


# --------------------------- Results (API) ---------------------------
@app.get("/api/results")
@login_required
def api_results_list():
    company_id = request.args.get("company_id")
    conn = db_connect()
    cur = conn.cursor()
    if company_id:
        try:
            cid = int(company_id)
            cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id WHERE r.company_id = ? ORDER BY r.id DESC LIMIT 100", (cid,))
        except Exception:
            cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id ORDER BY r.id DESC LIMIT 100")
    else:
        cur.execute("SELECT r.*, c.name FROM results r JOIN companies c ON r.company_id = c.id ORDER BY r.id DESC LIMIT 100")
    rows = cur.fetchall()
    explanations = {}
    for r in rows:
        rid = r["id"]
        items = build_human_explanations(r["detail"] or "")
        explanations[str(rid)] = items
    conn.close()
    return jsonify({"ok": True, "results": rows_to_list(rows), "explanations": explanations})


# --------------------------- Schedules (API) ---------------------------
@app.get("/api/schedules")
@login_required
def api_schedules_list():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT s.*, c.name FROM schedules s JOIN companies c ON s.company_id = c.id ORDER BY s.id DESC")
    rows = cur.fetchall()
    conn.close()
    return jsonify({"ok": True, "schedules": rows_to_list(rows)})

@app.post("/api/schedules")
@login_required
def api_schedules_create():
    data = request.get_json(silent=True) or {}
    company_id = int(data.get("company_id") or 0)
    interval_minutes = int(data.get("interval_minutes") or 60)
    active = 1
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("INSERT INTO schedules(company_id, interval_minutes, active, next_run) VALUES (?,?,?,?)",
                (company_id, interval_minutes, active, 0))
    sid = cur.lastrowid
    conn.commit()
    cur.execute("SELECT * FROM schedules WHERE id = ?", (sid,))
    s = cur.fetchone()
    conn.close()
    return jsonify({"ok": True, "schedule": row_to_dict(s)})

@app.patch("/api/schedules/<int:schedule_id>")
@login_required
def api_schedules_toggle(schedule_id: int):
    data = request.get_json(silent=True) or {}
    active = 1 if bool(data.get("active", True)) else 0
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("UPDATE schedules SET active=? WHERE id=?", (active, schedule_id))
    conn.commit()
    cur.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,))
    s = cur.fetchone()
    conn.close()
    return jsonify({"ok": True, "schedule": row_to_dict(s)})

@app.post("/api/run-now")
@login_required
def api_run_now():
    data = request.get_json(silent=True) or {}
    company_id = int(data.get("company_id") or 0)
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    c = cur.fetchone()
    conn.close()
    if not c:
        return jsonify({"ok": False, "error": "not_found"}), 404
    try:
        run_tests_for_company(c)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# --------------------------- Pricing & Payments (API) ---------------------------
@app.get("/api/pricing")
@login_required
def api_pricing():
    plan_features = {
        "basic": [
            "Aylık temel güvenlik taraması",
            "HTTP güvenlik başlıkları analizi",
            "Açık port hızlı kontrol (80/443/22 vb.)",
            "Basit HTML yorum/metadata sızıntı kontrolü",
            "Rapor özeti ve öneriler",
        ],
        "pro": [
            "Haftalık kapsamlı tarama",
            "Basic kapsamındaki tüm kontroller",
            "Alt alan (subdomain) keşfi ve HTTP kontrolü",
            "İçerik güvenliği (CSP) ve X-Frame-Options detay analizi",
            "Gelişmiş öneriler ve takip",
        ],
        "enterprise": [
            "Günlük otomatik tarama ve bildirim",
            "Pro kapsamındaki tüm kontroller",
            "Özel kural setleri ve eşik değerleri",
            "Özel entegrasyon (SMTP/Webhook) desteği",
            "Öncelikli destek ve danışmanlık",
        ],
    }
    plan_tests = [
        {"name": "HTTP Güvenlik Başlıkları", "basic": True, "pro": True, "enterprise": True},
        {"name": "CSP / X-Frame-Options Analizi", "basic": False, "pro": True, "enterprise": True},
        {"name": "Açık Port Kontrolü (80/443/22)", "basic": True, "pro": True, "enterprise": True},
        {"name": "Geniş Port Taraması (top 1000)", "basic": False, "pro": True, "enterprise": True},
        {"name": "Temel Sızma Testleri (güvenli)", "basic": False, "pro": True, "enterprise": True},
        {"name": "Alt Alan (Subdomain) Keşfi", "basic": False, "pro": True, "enterprise": True},
        {"name": "HTML Yorum/Metadata Sızıntı Kontrolü", "basic": True, "pro": True, "enterprise": True},
        {"name": "DNS/HTTP Doğrulama Takibi", "basic": True, "pro": True, "enterprise": True},
        {"name": "Otomatik Tarama Sıklığı", "basic": "Aylık", "pro": "Haftalık", "enterprise": "Günlük"},
        {"name": "Bildirim Entegrasyonları (SMTP/Webhook)", "basic": False, "pro": False, "enterprise": True},
        {"name": "Özel Kural ve Eşikler", "basic": False, "pro": False, "enterprise": True},
    ]
    return jsonify({"ok": True, "prices": PRICES_TRY, "plan_features": plan_features, "plan_tests": plan_tests})

@app.get("/api/payments")
@login_required
def api_payments_list():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT p.*, c.name AS company_name, u.username AS user_name
        FROM payments p
        LEFT JOIN companies c ON p.company_id = c.id
        LEFT JOIN users u ON p.user_id = u.id
        ORDER BY p.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return jsonify({"ok": True, "payments": rows_to_list(rows)})

@app.post("/api/checkout")
@login_required
def api_checkout():
    data = request.get_json(silent=True) or {}
    company_id = int(data.get("company_id") or 0)
    plan = (data.get("plan") or "basic").strip()
    if plan not in PRICES_TRY:
        return jsonify({"ok": False, "error": "invalid_plan"}), 400
    amount = PRICES_TRY[plan]
    currency = "try"
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO payments(user_id, company_id, plan, amount, currency, status, provider, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (g.user["id"], company_id, plan, amount, currency, "initiated", "offline", int(time.time())),
    )
    payment_id = cur.lastrowid
    conn.commit()
    try:
        cur.execute("UPDATE payments SET status=?, receipt_url=? WHERE id=?", ("paid", "#", payment_id))
        cur.execute("UPDATE companies SET package=? WHERE id=?", (plan, company_id))
        conn.commit()
        cur.execute("SELECT * FROM payments WHERE id=?", (payment_id,))
        p = cur.fetchone()
        conn.close()
        return jsonify({"ok": True, "payment": row_to_dict(p)})
    except Exception as e:
        conn.close()
        return jsonify({"ok": False, "error": str(e)}), 500


# --------------------------- Public Order (API) ---------------------------
@app.post("/api/order")
def api_public_order_submit():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    target_url = normalize_url(data.get("target_url") or "")
    plan = (data.get("plan") or "basic").strip()
    if plan not in ("basic","pro","enterprise"):
        plan = "basic"
    if not name or not target_url or not email:
        return jsonify({"ok": False, "error": "validation"}), 400
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
    now = int(time.time())
    bucket = ORDER_RATE.get(ip, [])
    bucket = [t for t in bucket if now - t < 3600]
    if len(bucket) >= 3:
        return jsonify({"ok": False, "error": "rate_limited"}), 429
    bucket.append(now)
    ORDER_RATE[ip] = bucket

    host = get_host_from_url(target_url)
    edom = email_domain(email)
    if not domains_match(edom, host):
        return jsonify({"ok": False, "error": "email_domain_mismatch"}), 400
    try:
        pc_conn = db_connect()
        pc_cur = pc_conn.cursor()
        pc_cur.execute("SELECT * FROM settings ORDER BY id DESC LIMIT 1")
        st = pc_cur.fetchone()
        pc_conn.close()
        policy = st["verification_policy"] if st and "verification_policy" in st.keys() else "http_and_dns"
    except Exception:
        policy = "http_and_dns"
    token = os.urandom(16).hex()
    method = 'http_and_dns'
    conn = db_connect()
    cur = conn.cursor()
    if policy == 'email_link':
        email_token = os.urandom(20).hex()
        method = 'email_link'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method, email_verify_token) VALUES (?,?,?,?,0,?,?,?)",
            (name, email, plan, target_url, token, method, email_token)
        )
    elif policy == 'http_only':
        method = 'http_file'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method) VALUES (?,?,?,?,0,?,?)",
            (name, email, plan, target_url, token, method)
        )
    elif policy == 'dns_only':
        method = 'dns_txt'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method) VALUES (?,?,?,?,0,?,?)",
            (name, email, plan, target_url, token, method)
        )
    elif policy == 'standard':
        method = 'http_and_dns'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method) VALUES (?,?,?,?,0,?,?)",
            (name, email, plan, target_url, token, method)
        )
    else:
        method = 'http_and_dns'
        cur.execute(
            "INSERT INTO companies(name, email, package, target_url, verified, verify_token, verify_method) VALUES (?,?,?,?,0,?,?)",
            (name, email, plan, target_url, token, method)
        )
    company_id = cur.lastrowid
    conn.commit()
    cur.execute("SELECT * FROM companies WHERE id = ?", (company_id,))
    company = cur.fetchone()
    conn.close()
    try:
        parsed = urlparse(target_url)
        scheme = parsed.scheme or "https"
        h = parsed.netloc or parsed.path
        verify_url = f"{scheme}://{h}/.well-known/pentest-verify.txt"
        if policy == 'email_link':
            link = f"{request.url_root.rstrip('/')}{url_for('email_verify')}?company_id={company_id}&token={company['email_verify_token']}"
            body = (
                "Test talebiniz alındı. Devam etmek için aşağıdaki doğrulama linkine tıklayın.\n\n"
                f"Alan eşleşen e-posta doğrulaması: {link}\n\n"
                "Link çalışmıyorsa bizimle iletişime geçin."
            )
        elif policy == 'http_only':
            body = (
                "Test talebiniz alındı. Devam edebilmek için alan sahipliğini doğrulayın.\n\n"
                f"HTTP dosya doğrulaması: {verify_url} konumunda içeriği SADECE şu token olan dosyayı yayınlayın:\n{token}\n"
            )
        elif policy == 'dns_only':
            body = (
                "Test talebiniz alındı. Devam edebilmek için alan sahipliğini doğrulayın.\n\n"
                f"DNS TXT doğrulaması: {h} için TXT kaydına şu değeri ekleyin:\n{token}\n"
            )
        elif policy == 'standard':
            body = (
                "Test talebiniz alındı. Devam edebilmek için alan sahipliğini doğrulayın.\n\n"
                f"HTTP dosya doğrulaması: {verify_url} konumunda içeriği SADECE şu token olan dosyayı yayınlayın:\n{token}\n\n"
                f"VEYA DNS TXT doğrulaması: {h} için TXT kaydına şu değeri ekleyin:\n{token}\n"
            )
        else:
            body = (
                "Test talebiniz alındı. Devam edebilmek için alan sahipliğini doğrulayın.\n\n"
                f"1) HTTP dosya doğrulaması: {verify_url} konumunda içeriği SADECE şu token olan dosyayı yayınlayın:\n{token}\n\n"
                f"2) DNS TXT doğrulaması: {h} için TXT kaydına şu değeri ekleyin:\n{token}\n\n"
                "Her iki doğrulama başarılı olduktan sonra sistem taramayı etkinleştirmenize izin verecektir."
            )
        notify(email, "Alan Doğrulama Talimatları", body)
    except Exception as e:
        print(f"[ORDER/API] Notify error: {e}")
    return jsonify({"ok": True, "company_id": company_id})


if __name__ == "__main__":
    db_init()
    db_migrate()
    create_default_company_if_empty()
    create_default_admin_if_empty()
    thread.start()
    # Port yapılandırılabilir olsun; varsayılan 5000
    try:
        port = int(os.environ.get("PORT", "5000"))
    except Exception:
        port = 5000
    app.run(host="127.0.0.1", port=port)