#!/usr/bin/env python3
"""
NetWatch – kleiner NetAlertX-Ersatz für OPNsense.

- Holt ARP-Tabelle + DHCP-Leases über die OPNsense-API
- Ordnet Geräte nach VLAN (192.168.<VLAN>.x)
- Web-UI zum Benennen / Beobachten von Geräten
- Online-Prüfung (Ping + ARP)
- Telegram-Benachrichtigungen + Bot-Befehle (/online, /offline, /status <name>)

Nur Python-Standardbibliothek, keine Abhängigkeiten.
"""
import base64
import ipaddress
import json
import logging
import os
import queue
import secrets
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------
# Konfiguration
# --------------------------------------------------------------------------


def env(key, default=None):
    v = os.environ.get(key)
    return default if v is None or v.strip() == "" else v.strip()


def env_bool(key, default=False):
    v = os.environ.get(key)
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "ja")


def env_int(key, default):
    try:
        return int(env(key, default))
    except (TypeError, ValueError):
        return default


OPN_URL = (env("OPNSENSE_URL", "https://192.168.10.1") or "").rstrip("/")
OPN_KEY = env("OPNSENSE_KEY", "")
OPN_SECRET = env("OPNSENSE_SECRET", "")
OPN_VERIFY_SSL = env_bool("OPNSENSE_VERIFY_SSL", False)

SUBNET_PREFIX = env("SUBNET_PREFIX", "192.168")
VLANS = [int(x) for x in env("VLANS", "10,20,30,40,50,60,70,80,90").split(",") if x.strip()]
VLAN_NAMES = {}
for part in env("VLAN_NAMES", "").split(","):
    if ":" in part:
        k, v = part.split(":", 1)
        try:
            VLAN_NAMES[int(k.strip())] = v.strip()
        except ValueError:
            pass

SCAN_INTERVAL = env_int("SCAN_INTERVAL", 60)
OFFLINE_AFTER = env_int("OFFLINE_AFTER_CHECKS", 3)        # so viele Fehlversuche bis "offline"
ONLINE_MODE = env("ONLINE_MODE", "ping_or_arp")            # ping_or_arp | ping | arp
PING_TIMEOUT = env_int("PING_TIMEOUT", 1)
PING_WORKERS = env_int("PING_WORKERS", 64)
INCLUDE_FIREWALL = env_bool("INCLUDE_FIREWALL", False)     # eigene Interfaces der OPNsense anzeigen

TG_TOKEN = env("TELEGRAM_BOT_TOKEN", "")
TG_CHAT = env("TELEGRAM_CHAT_ID", "")
TG_COMMANDS = env_bool("TELEGRAM_COMMANDS", True)
NOTIFY_NEW = env_bool("NOTIFY_NEW_DEVICES", True)
WATCH_DEFAULT = env_bool("WATCH_NEW_DEVICES", False)       # neue Geräte automatisch beobachten?
MERGE_RANDOM_MAC = env_bool("MERGE_RANDOM_MAC", True)      # private MAC + gleicher Hostname = gleiches Gerät
NOTIFY_RANDOM_MAC = env_bool("NOTIFY_RANDOM_MAC", True)    # Meldung auch für unbekannte Geräte mit privater MAC

UNIFI_URL = (env("UNIFI_URL", "") or "").rstrip("/")      # leer = UniFi deaktiviert
UNIFI_USER = env("UNIFI_USER", "")
UNIFI_PASSWORD = env("UNIFI_PASSWORD", "")
UNIFI_SITE = env("UNIFI_SITE", "default")
UNIFI_IS_OS = env_bool("UNIFI_IS_UNIFI_OS", True)           # UDM / Cloud Key Gen2 / UniFi OS Server
UNIFI_VERIFY_SSL = env_bool("UNIFI_VERIFY_SSL", False)
UNIFI_USE_NAMES = env_bool("UNIFI_USE_NAMES", True)         # Aliasnamen aus UniFi übernehmen

WEB_PORT = env_int("WEB_PORT", 8080)
WEB_USER = env("WEB_USER", "admin")
WEB_PASSWORD = env("WEB_PASSWORD", "")
DB_PATH = env("DB_PATH", "/data/netwatch.db")

logging.basicConfig(level=env("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("netwatch")

HERE = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------
# Datenbank
# --------------------------------------------------------------------------

db_lock = threading.RLock()
_db = None


def db():
    global _db
    if _db is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        _db = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db.row_factory = sqlite3.Row
        _db.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                mac         TEXT NOT NULL,
                vlan        INTEGER NOT NULL,
                ip          TEXT,
                name        TEXT DEFAULT '',
                hostname    TEXT DEFAULT '',
                vendor      TEXT DEFAULT '',
                interface   TEXT DEFAULT '',
                first_seen  INTEGER,
                last_seen   INTEGER,
                online      INTEGER DEFAULT 0,
                fails       INTEGER DEFAULT 0,
                watch       INTEGER DEFAULT 0,
                changed_at  INTEGER,
                UNIQUE(mac, vlan)
            );
            CREATE TABLE IF NOT EXISTS events (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     INTEGER,
                device INTEGER,
                kind   TEXT,
                text   TEXT
            );
            CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
            """
        )
        cols = {r["name"] for r in _db.execute("PRAGMA table_info(devices)")}
        for col in ("unifi_name", "conn"):
            if col not in cols:
                _db.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT DEFAULT ''")
        ecols = {r["name"] for r in _db.execute("PRAGMA table_info(events)")}
        if "tg" not in ecols:
            _db.execute("ALTER TABLE events ADD COLUMN tg TEXT DEFAULT ''")
        _db.commit()
    return _db


def kv_get(k, default=None):
    with db_lock:
        r = db().execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def kv_set(k, v):
    with db_lock:
        db().execute("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", (k, str(v)))
        db().commit()


EVENT_KEEP = 5000


def add_event(device_id, kind, text, tg=""):
    """tg: '' = keine Telegram-Nachricht, 'queued' / 'sent' / 'error: …'"""
    with db_lock:
        cur = db().execute("INSERT INTO events(ts,device,kind,text,tg) VALUES(?,?,?,?,?)",
                           (int(time.time()), device_id, kind, text, tg))
        db().execute(f"DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT {EVENT_KEEP})")
        db().commit()
        return cur.lastrowid


def set_event_tg(event_id, tg):
    if not event_id:
        return
    with db_lock:
        db().execute("UPDATE events SET tg=? WHERE id=?", (tg, event_id))
        db().commit()


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------


def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if len(mac) == 17 else ""


def is_random_mac(mac):
    """Lokal administrierte MAC (2. Hex-Ziffer 2/6/A/E) = private/zufällige Adresse (iOS, Android, Windows)."""
    return len(mac or "") == 17 and mac[1].lower() in "26ae"


def vlan_of(ip):
    """192.168.<vlan>.x -> vlan, sonst 0 (= 'Andere')."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except Exception:
        return None
    if addr.is_link_local or addr.is_unspecified or addr.is_multicast or ip.endswith(".255"):
        return None  # 169.254.x.x (kein DHCP), 0.0.0.0 usw. ignorieren
    parts = ip.split(".")
    prefix = SUBNET_PREFIX.split(".")
    if parts[: len(prefix)] != prefix:
        return 0
    try:
        third = int(parts[2])
    except (IndexError, ValueError):
        return 0
    return third if third in VLANS else 0


def vlan_label(v):
    if v == 0:
        return "Andere"
    name = VLAN_NAMES.get(v)
    return f"VLAN {v}" + (f" · {name}" if name else "")


def display_name(d):
    return (d.get("name") or (d.get("unifi_name") if UNIFI_USE_NAMES else "")
            or d.get("hostname") or d.get("ip") or d.get("mac"))


def ip_sort_key(ip):
    try:
        return int(ipaddress.IPv4Address(ip or "0.0.0.0"))
    except Exception:
        return 0


# --------------------------------------------------------------------------
# OPNsense API
# --------------------------------------------------------------------------


class OPNsense:
    def __init__(self):
        self.ctx = ssl.create_default_context()
        if not OPN_VERIFY_SSL:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        token = base64.b64encode(f"{OPN_KEY}:{OPN_SECRET}".encode()).decode()
        self.headers = {"Authorization": "Basic " + token, "Accept": "application/json"}
        self.lease_endpoint = None  # wird beim ersten erfolgreichen Abruf gemerkt

    def _req(self, path, payload=None):
        url = OPN_URL + path
        data = None
        headers = dict(self.headers)
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        # Proxy-Variablen für das lokale Netz ignorieren
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=self.ctx))
        with opener.open(req, timeout=20) as r:
            return json.loads(r.read().decode() or "null")

    def arp(self):
        """Liste von dicts mit mac, ip, intf, manufacturer, hostname, expired, permanent."""
        try:
            return self._arp()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise RuntimeError("401 – API-Key/Secret falsch (OPNSENSE_KEY / OPNSENSE_SECRET prüfen)")
            if e.code == 403:
                raise RuntimeError("403 – API-Benutzer fehlt das Recht 'Diagnostics: ARP Table' "
                                   "(System > Zugang > Benutzer > Effektive Rechte)")
            raise
        except urllib.error.URLError as e:
            raise RuntimeError(f"OPNsense nicht erreichbar unter {OPN_URL}: {e.reason}")

    def _arp(self):
        try:
            res = self._req("/api/diagnostics/interface/getArp")
            if isinstance(res, list):
                return res
            if isinstance(res, dict) and isinstance(res.get("rows"), list):
                return res["rows"]
        except urllib.error.HTTPError as e:
            if e.code not in (404, 400):
                raise
        # neuere Versionen: search_arp
        res = self._req("/api/diagnostics/interface/search_arp", {"current": 1, "rowCount": -1})
        return res.get("rows", []) if isinstance(res, dict) else []

    def leases(self):
        """DHCP-Leases (ISC, Kea oder Dnsmasq) -> Liste von dicts (mac, ip, hostname)."""
        candidates = [
            ("/api/dnsmasq/leases/search", "dnsmasq"),
            ("/api/kea/leases4/search", "kea"),
            ("/api/dhcpv4/leases/searchLease", "isc"),
        ]
        if self.lease_endpoint:
            candidates.sort(key=lambda c: c[0] != self.lease_endpoint)
        out = []
        for path, kind in candidates:
            try:
                res = self._req(path, {"current": 1, "rowCount": -1, "searchPhrase": ""})
            except Exception:
                continue
            rows = res.get("rows") if isinstance(res, dict) else None
            if not rows:
                continue
            self.lease_endpoint = path
            for r in rows:
                mac = norm_mac(r.get("mac") or r.get("hwaddr") or r.get("hw_address"))
                ip = r.get("address") or r.get("ip") or r.get("ip_address") or ""
                host = r.get("hostname") or r.get("client-hostname") or r.get("client_hostname") or ""
                if mac and ip:
                    out.append({"mac": mac, "ip": ip, "hostname": host})
            break
        return out


opn = OPNsense()

# --------------------------------------------------------------------------
# UniFi (optional)
# --------------------------------------------------------------------------


class UniFi:
    """Liest verbundene Clients aus dem UniFi Network Controller (UniFi OS oder klassisch)."""

    def __init__(self):
        self.ctx = ssl.create_default_context()
        if not UNIFI_VERIFY_SSL:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.cookies = {}
        self.csrf = ""
        self.base = UNIFI_URL + ("/proxy/network" if UNIFI_IS_OS else "")
        self.ap_names = {}
        self.ap_names_ts = 0

    @property
    def enabled(self):
        return bool(UNIFI_URL and UNIFI_USER and UNIFI_PASSWORD)

    def _open(self, url, payload=None):
        headers = {"Accept": "application/json"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=self.ctx))
        r = opener.open(req, timeout=20)
        for c in r.headers.get_all("Set-Cookie") or []:
            k, _, rest = c.partition("=")
            self.cookies[k.strip()] = rest.split(";", 1)[0]
        tok = r.headers.get("X-CSRF-Token") or r.headers.get("X-Updated-CSRF-Token")
        if tok:
            self.csrf = tok
        return json.loads(r.read().decode() or "null")

    def login(self):
        self.cookies, self.csrf = {}, ""
        path = "/api/auth/login" if UNIFI_IS_OS else "/api/login"
        self._open(UNIFI_URL + path, {"username": UNIFI_USER, "password": UNIFI_PASSWORD, "remember": True})

    def _get(self, path):
        url = f"{self.base}/api/s/{UNIFI_SITE}/{path}"
        try:
            if not self.cookies:
                self.login()
            return self._open(url)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self.login()
                return self._open(url)
            raise

    def _devices(self):
        if time.time() - self.ap_names_ts > 600:
            try:
                res = self._get("stat/device")
                self.ap_names = {norm_mac(d.get("mac")): d.get("name") or d.get("model") or ""
                                 for d in res.get("data", [])}
                self.ap_names_ts = time.time()
            except Exception as e:
                log.debug("UniFi stat/device: %s", e)
        return self.ap_names

    def clients(self):
        """mac -> {ip, name, hostname, conn, vendor}. Nur aktuell verbundene Clients."""
        res = self._get("stat/sta")
        names = self._devices()
        out = {}
        now = time.time()
        for c in res.get("data", []):
            mac = norm_mac(c.get("mac"))
            ip = c.get("ip") or c.get("last_ip") or ""
            if not mac:
                continue
            if c.get("last_seen") and now - c["last_seen"] > 300:
                continue
            if c.get("is_wired"):
                sw = names.get(norm_mac(c.get("sw_mac")), "") or "Switch"
                conn = f"🔌 {sw}" + (f" Port {c['sw_port']}" if c.get("sw_port") else "")
            else:
                ap = names.get(norm_mac(c.get("ap_mac")), "") or "AP"
                conn = f"📶 {c.get('essid', '')} @ {ap}"
                if c.get("signal"):
                    conn += f" ({c['signal']} dBm)"
            out[mac] = {"ip": ip, "name": c.get("name") or "", "hostname": c.get("hostname") or "",
                        "conn": conn.strip(), "vendor": c.get("oui") or ""}
        return out


unifi = UniFi()

# --------------------------------------------------------------------------
# Telegram
# --------------------------------------------------------------------------


class TelegramError(Exception):
    def __init__(self, msg, retry_after=0):
        super().__init__(msg)
        self.retry_after = retry_after


def tg_api(method, payload, timeout=15):
    url = f"https://api.telegram.org/bot{TG_TOKEN}/{method}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {}
        desc = body.get("description") or f"HTTP {e.code}"
        retry = (body.get("parameters") or {}).get("retry_after", 0)
        raise TelegramError(desc, retry)
    except urllib.error.URLError as e:
        raise TelegramError(f"api.telegram.org nicht erreichbar: {e.reason}")


tg_queue = queue.Queue()
tg_state = {"last_error": "", "last_ok": 0}


def tg_send_now(text, chat_id=None):
    """Sofort senden, mit Wiederholung bei Rate-Limit. Gibt (ok, fehler) zurück."""
    if not TG_TOKEN or not (chat_id or TG_CHAT):
        return False, "Telegram nicht konfiguriert (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID fehlen)"
    payload = {"chat_id": chat_id or TG_CHAT, "text": text,
               "parse_mode": "HTML", "disable_web_page_preview": True}
    err = ""
    for attempt in range(5):
        try:
            tg_api("sendMessage", payload)
            tg_state["last_ok"] = int(time.time())
            tg_state["last_error"] = ""
            return True, ""
        except TelegramError as e:
            err = str(e)
            if e.retry_after:                      # 429 Too Many Requests
                time.sleep(e.retry_after + 1)
                continue
            if "can't parse entities" in err:      # Formatierungsproblem -> ohne HTML senden
                payload.pop("parse_mode", None)
                continue
            if "nicht erreichbar" in err and attempt < 4:
                time.sleep(5 * (attempt + 1))
                continue
            break
    tg_state["last_error"] = err
    log.warning("Telegram-Fehler: %s", err)
    return False, err


def tg_send(text, chat_id=None, event_id=None):
    """In die Warteschlange legen (blockiert den Scan nicht)."""
    if not TG_TOKEN or not (chat_id or TG_CHAT):
        set_event_tg(event_id, "error: Telegram nicht konfiguriert")
        return False
    tg_queue.put((text, chat_id, event_id))
    return True


def tg_worker():
    while True:
        text, chat_id, event_id = tg_queue.get()
        ok, err = tg_send_now(text, chat_id)
        set_event_tg(event_id, "sent" if ok else f"error: {err}")
        time.sleep(1.1)  # Telegram erlaubt ca. 1 Nachricht/Sekunde pro Chat


def esc(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def fmt_device(d):
    lines = [f"<b>{esc(display_name(d))}</b>"]
    if d.get("hostname") and d.get("hostname") != display_name(d):
        lines.append(f"Hostname: {esc(d['hostname'])}")
    lines.append(f"{esc(vlan_label(d['vlan']))} · {esc(d['ip'])}")
    lines.append(f"<code>{esc(d['mac'])}</code> {esc(d['vendor'])}".strip()
                 + (" · private MAC" if is_random_mac(d.get("mac")) else ""))
    if d.get("conn"):
        lines.append(esc(d["conn"]))
    return "\n".join(lines)


def fmt_new_device(d):
    return ("🆕 <b>Neues Gerät im Netz</b>\n"
            f"Name: <b>{esc(d.get('unifi_name') or d.get('hostname') or 'unbekannt (kein Hostname gemeldet)')}</b>\n"
            + (f"Hostname: {esc(d['hostname'])}\n" if d.get("unifi_name") and d.get("hostname") else "")
            + (f"Verbindung: {esc(d['conn'])}\n" if d.get("conn") else "") +
            f"Hersteller: {esc(d.get('vendor') or '-')}\n"
            f"{esc(vlan_label(d['vlan']))} · IP {esc(d['ip'])}\n"
            f"MAC <code>{esc(d['mac'])}</code>\n"
            f"Interface: {esc(d.get('interface') or '-')}")


def find_devices(devs, arg):
    """Erst exakter Treffer (Name, Hostname, IP, MAC), dann Teiltreffer."""
    arg = arg.lower()
    def fields(d):
        return [(d.get("name") or "").lower(), (d.get("unifi_name") or "").lower(),
                (d.get("hostname") or "").lower(), d.get("ip") or "", d.get("mac") or ""]
    exact = [d for d in devs if arg in fields(d)]
    if exact:
        return exact
    return [d for d in devs if any(arg in f for f in fields(d) if f)]


def tg_bot_loop():
    """Einfache Bot-Befehle per Long-Polling."""
    offset = int(kv_get("tg_offset", "0"))
    log.info("Telegram-Bot-Befehle aktiv")
    try:  # Befehlsmenü in Telegram anzeigen
        tg_api("setMyCommands", {"commands": [
            {"command": "check", "description": "Onlinestatus eines Geräts (Name/IP/MAC)"},
            {"command": "online", "description": "Alle Geräte online [vlan]"},
            {"command": "offline", "description": "Alle Geräte offline [vlan]"},
            {"command": "status", "description": "Übersicht"},
            {"command": "scan", "description": "Sofort scannen"},
        ]})
    except Exception as e:
        log.debug("setMyCommands: %s", e)
    while True:
        try:
            res = tg_api("getUpdates", {"timeout": 50, "offset": offset}, timeout=60)
            for upd in res.get("result", []):
                offset = upd["update_id"] + 1
                kv_set("tg_offset", offset)
                msg = upd.get("message") or {}
                chat = str((msg.get("chat") or {}).get("id", ""))
                text = (msg.get("text") or "").strip()
                if not text.startswith("/") or chat != str(TG_CHAT):
                    continue
                tg_send_now(handle_command(text), chat)
        except Exception as e:
            log.debug("Telegram-Polling: %s", e)
            time.sleep(10)


def handle_command(text):
    cmd, _, arg = text.partition(" ")
    cmd = cmd.split("@")[0].lower()
    arg = arg.strip().lower()
    devs = list_devices()
    if cmd in ("/online", "/offline"):
        want = 1 if cmd == "/online" else 0
        sel = [d for d in devs if d["online"] == want]
        if arg:
            sel = [d for d in sel if str(d["vlan"]) == arg]
        if not sel:
            return "Keine Geräte."
        lines, cur = [], None
        for d in sorted(sel, key=lambda d: (d["vlan"] or 999, ip_sort_key(d["ip"]))):
            if d["vlan"] != cur:
                cur = d["vlan"]
                lines.append(f"\n<b>{esc(vlan_label(cur))}</b>")
            lines.append(f"{'🟢' if want else '🔴'} {esc(display_name(d))} – {esc(d['ip'])}")
        return ("Online" if want else "Offline") + f" ({len(sel)}):" + "\n".join(lines)
    if cmd in ("/check", "/status"):
        if not arg:
            on = sum(d["online"] for d in devs)
            return f"{on} von {len(devs)} Geräten online.\nNutze /check &lt;name|ip|mac&gt;"
        hits = find_devices(devs, arg)
        if not hits:
            return f"Kein Gerät „{esc(arg)}“ gefunden."
        hits = hits[:10]
        live = {}
        if cmd == "/check" and ONLINE_MODE != "arp":
            # Live-Ping, damit die Antwort aktuell ist und nicht vom letzten Scan stammt
            with ThreadPoolExecutor(max_workers=10) as ex:
                live = dict(zip([d["id"] for d in hits], ex.map(lambda d: ping(d["ip"]) if d["ip"] else False, hits)))
        out = []
        for d in hits:
            ts = datetime.fromtimestamp(d["last_seen"]).strftime("%d.%m. %H:%M") if d["last_seen"] else "-"
            if d["id"] in live:
                if live[d["id"]]:
                    status = "🟢 online (antwortet auf Ping)"
                elif d["online"]:
                    status = "🟡 kein Ping, laut Firewall aber noch aktiv"
                else:
                    status = "🔴 offline"
            else:
                status = "🟢 online" if d["online"] else "🔴 offline"
            out.append(f"{status}\n{fmt_device(d)}\nZuletzt gesehen: {ts}")
        return "\n\n".join(out)
    if cmd == "/scan":
        threading.Thread(target=scan_once, daemon=True).start()
        return "Scan gestartet."
    return ("Befehle:\n/check NAME – Onlinestatus prüfen (live, auch IP oder MAC)\n"
            "/online [vlan] – Geräte online\n/offline [vlan] – Geräte offline\n"
            "/status – Übersicht\n/scan – sofort scannen")


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------

scan_lock = threading.Lock()
state = {"last_scan": 0, "last_error": "", "duration": 0, "unifi_error": ""}


def ping(ip):
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=PING_TIMEOUT + 2)
        return r.returncode == 0
    except Exception:
        return False


def list_devices():
    with db_lock:
        return [dict(r) for r in db().execute("SELECT * FROM devices")]


def scan_once():
    if not scan_lock.acquire(blocking=False):
        return
    t0 = time.time()
    try:
        now = int(t0)
        arp = opn.arp()
        try:
            leases = opn.leases()
        except Exception as e:
            log.debug("Leases nicht verfügbar: %s", e)
            leases = []
        lease_by_mac = {l["mac"]: l for l in leases}

        # Was die Firewall gerade sieht: (mac, vlan) -> info
        seen = {}
        for e in arp:
            mac = norm_mac(e.get("mac"))
            ip = (e.get("ip") or "").strip()
            if not mac or not ip:
                continue
            if not INCLUDE_FIREWALL and str(e.get("permanent")).lower() in ("true", "1", "yes"):
                continue
            if mac == "ff:ff:ff:ff:ff:ff":
                continue
            v = vlan_of(ip)
            if v is None:
                continue
            expired = str(e.get("expired")).lower() in ("true", "1", "yes")
            host = e.get("hostname") or lease_by_mac.get(mac, {}).get("hostname", "")
            seen[(mac, v)] = {
                "ip": ip, "hostname": host or "", "vendor": e.get("manufacturer") or "",
                "interface": e.get("intf_description") or e.get("intf") or "",
                "arp_ok": not expired, "unifi_ok": False, "unifi_name": "", "conn": "",
            }
        # Leases ergänzen (Geräte mit Lease, aber ohne ARP-Eintrag)
        for l in leases:
            v = vlan_of(l["ip"])
            if v is None:
                continue
            key = (l["mac"], v)
            if key not in seen:
                seen[key] = {"ip": l["ip"], "hostname": l["hostname"], "vendor": "", "interface": "",
                             "arp_ok": False, "unifi_ok": False, "unifi_name": "", "conn": ""}
        # UniFi-Clients: verbunden = online, plus Aliasname und Verbindung (AP/SSID/Switch-Port)
        uni = {}
        if unifi.enabled:
            try:
                uni = unifi.clients()
                state["unifi_error"] = ""
            except Exception as e:
                state["unifi_error"] = f"{type(e).__name__}: {e}"
                log.warning("UniFi-Abfrage fehlgeschlagen: %s", e)
        for mac, c in uni.items():
            v = vlan_of(c["ip"]) if c["ip"] else None
            if v is None:
                continue
            key = (mac, v)
            info = seen.setdefault(key, {"ip": c["ip"], "hostname": c["hostname"], "vendor": c["vendor"],
                                         "interface": "", "arp_ok": False})
            info["unifi_ok"] = True
            info["unifi_name"] = c["name"]
            info["conn"] = c["conn"]
            if not info.get("hostname"):
                info["hostname"] = c["hostname"]
            if not info.get("vendor"):
                info["vendor"] = c["vendor"]

        with db_lock:
            known = {(r["mac"], r["vlan"]): dict(r) for r in db().execute("SELECT * FROM devices")}
        first_scan = not known

        # Neue Geräte anlegen – vorher prüfen, ob es ein bekanntes Gerät ist, das nur
        # das WLAN/VLAN gewechselt hat oder eine neue private MAC verwendet
        new_devices, moves = [], []
        with db_lock:
            for key, info in seen.items():
                if key in known:
                    continue
                mac, v = key
                host = (info.get("hostname") or "").strip().lower()
                uname = (info.get("unifi_name") or "").strip().lower()

                def same_device(k, d):
                    if k in seen:            # alter Eintrag ist gerade selbst aktiv -> anderes Gerät
                        return False
                    if k[0] == mac:          # gleiche MAC, anderes VLAN (z. B. zweites WLAN)
                        return True
                    if MERGE_RANDOM_MAC and is_random_mac(mac) and (host or uname):
                        return ((host and (d.get("hostname") or "").strip().lower() == host) or
                                (uname and (d.get("unifi_name") or "").strip().lower() == uname))
                    return False

                cand = [d for k, d in known.items() if same_device(k, d)]
                if cand:
                    # bevorzugt gleiche MAC, sonst zuletzt gesehenes Gerät
                    old = max(cand, key=lambda d: (d["mac"] == mac, d.get("last_seen") or 0))
                    old_key = (old["mac"], old["vlan"])
                    try:
                        db().execute("UPDATE devices SET mac=?, vlan=? WHERE id=?", (mac, v, old["id"]))
                    except sqlite3.IntegrityError:
                        pass
                    else:
                        known.pop(old_key, None)
                        moves.append((old, dict(old), info))
                        old["mac"], old["vlan"] = mac, v
                        known[key] = old
                        continue

                cur = db().execute(
                    "INSERT INTO devices(mac,vlan,ip,hostname,vendor,interface,unifi_name,conn,first_seen,"
                    "last_seen,online,fails,watch,changed_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,0,?,?)",
                    (mac, v, info["ip"], info["hostname"], info["vendor"], info["interface"],
                     info.get("unifi_name", ""), info.get("conn", ""),
                     now, None, 1 if WATCH_DEFAULT else 0, now))
                d = dict(db().execute("SELECT * FROM devices WHERE id=?", (cur.lastrowid,)).fetchone())
                known[key] = d
                new_devices.append(d)
            db().commit()

        moved_ids = {m[0]["id"] for m in moves}

        # Online-Prüfung
        targets = {}
        for key, d in known.items():
            ip = seen.get(key, {}).get("ip") or d["ip"]
            if ip:
                targets[key] = ip
        ping_ok = {}
        if ONLINE_MODE in ("ping", "ping_or_arp") and targets:
            with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
                for key, ok in zip(targets.keys(), ex.map(ping, targets.values())):
                    ping_ok[key] = ok

        events = []
        with db_lock:
            for key, d in known.items():
                info = seen.get(key)
                arp_ok = bool(info and info["arp_ok"])
                uni_ok = bool(info and info.get("unifi_ok"))
                if ONLINE_MODE == "arp":
                    alive = arp_ok or uni_ok
                elif ONLINE_MODE == "ping":
                    alive = ping_ok.get(key, False) or uni_ok
                else:
                    alive = ping_ok.get(key, False) or arp_ok or uni_ok

                fails = 0 if alive else d["fails"] + 1
                online = d["online"]
                changed = d["changed_at"]
                if alive and not online:
                    online, changed = 1, now
                    if d["last_seen"]:  # nicht beim allerersten Sehen melden
                        events.append(("online", d))
                elif not alive and online and fails >= OFFLINE_AFTER:
                    online, changed = 0, now
                    events.append(("offline", d))

                fields = {"online": online, "fails": fails, "changed_at": changed}
                if alive:
                    fields["last_seen"] = now
                if info:
                    fields["ip"] = info["ip"]
                    if info["hostname"]:
                        fields["hostname"] = info["hostname"]
                    if info["vendor"]:
                        fields["vendor"] = info["vendor"]
                    if info["interface"]:
                        fields["interface"] = info["interface"]
                    if info.get("unifi_name"):
                        fields["unifi_name"] = info["unifi_name"]
                    if info.get("conn"):
                        fields["conn"] = info["conn"]
                if info and d["ip"] and info["ip"] != d["ip"] and d["id"] not in moved_ids:
                    events.append(("ipchange", {**d, "old_ip": d["ip"], "ip": info["ip"]}))
                sets = ",".join(f"{k}=?" for k in fields)
                db().execute(f"UPDATE devices SET {sets} WHERE id=?", (*fields.values(), d["id"]))
            db().commit()

        # Benachrichtigungen
        def notify(dev_id, kind, text, tg_text, send):
            eid = add_event(dev_id, kind, text, "queued" if send and TG_TOKEN and TG_CHAT else "")
            if send:
                tg_send(tg_text, event_id=eid)

        if first_scan and new_devices:
            # Erster Scan: eine Zusammenfassung statt einer Nachricht pro Gerät
            for d in new_devices:
                add_event(d["id"], "new", f"Erfasst beim ersten Scan: {display_name(d)} ({d['ip']})")
            per_vlan = {}
            for d in new_devices:
                per_vlan[d["vlan"]] = per_vlan.get(d["vlan"], 0) + 1
            lines = [f"{esc(vlan_label(v))}: {n}" for v, n in sorted(per_vlan.items(), key=lambda x: x[0] or 999)]
            notify(None, "info", f"Erster Scan: {len(new_devices)} Geräte erfasst",
                   f"📋 <b>NetWatch gestartet</b>\n{len(new_devices)} Geräte erfasst:\n" + "\n".join(lines)
                   + "\n\nAb jetzt kommt bei jedem neuen Gerät eine Nachricht.", NOTIFY_NEW)
        else:
            for d in new_devices:
                rnd = is_random_mac(d["mac"])
                msg = fmt_new_device(d)
                if rnd:
                    msg += ("\n\nℹ️ <i>Private (zufällige) MAC-Adresse – kann auch ein bekanntes Gerät sein, "
                            "das eine neue Adresse verwendet.</i>")
                notify(d["id"], "new", f"Neues Gerät: {display_name(d)} ({d['ip']})" + (" · private MAC" if rnd else ""),
                       msg, NOTIFY_NEW and (NOTIFY_RANDOM_MAC or not rnd))
        for d, before, info in moves:
            d = dict(d)
            for k in ("ip", "conn", "hostname"):
                if info.get(k):
                    d[k] = info[k]
            parts, tg_parts = [], []
            if before["vlan"] != d["vlan"]:
                parts.append(f"{vlan_label(before['vlan'])} → {vlan_label(d['vlan'])}")
                tg_parts.append(f"Vorher: {esc(vlan_label(before['vlan']))} · {esc(before['ip'])}")
            if before["mac"] != d["mac"]:
                parts.append(f"neue private MAC {before['mac']} → {d['mac']}")
                tg_parts.append(f"Vorherige MAC: <code>{esc(before['mac'])}</code>")
            kind = "vlanchange" if before["vlan"] != d["vlan"] else "macchange"
            title = "🔀 <b>Wechselt WLAN/VLAN</b>" if kind == "vlanchange" else "🔄 <b>Neue private MAC</b>"
            notify(d["id"], kind, f"{display_name(d)}: " + ", ".join(parts),
                   f"{title}\n{fmt_device(d)}\n" + "\n".join(tg_parts), bool(d["watch"]))
        for kind, d in events:
            if kind == "online":
                notify(d["id"], kind, f"{display_name(d)} ist online",
                       "🟢 <b>Online</b>\n" + fmt_device(d), bool(d["watch"]))
            elif kind == "offline":
                notify(d["id"], kind, f"{display_name(d)} ist offline",
                       "🔴 <b>Offline</b>\n" + fmt_device(d), bool(d["watch"]))
            elif kind == "ipchange":
                notify(d["id"], kind, f"{display_name(d)}: IP {d['old_ip']} → {d['ip']}",
                       f"🔁 <b>IP geändert</b> {esc(d['old_ip'])} → {esc(d['ip'])}\n" + fmt_device(d),
                       bool(d["watch"]))

        state["last_error"] = ""
        log.info("Scan: %d ARP, %d Leases, %d Geräte, %d neu", len(arp), len(leases), len(known), len(new_devices))
    except Exception as e:
        state["last_error"] = f"{type(e).__name__}: {e}"
        log.error("Scan fehlgeschlagen: %s", state["last_error"])
    finally:
        state["last_scan"] = int(time.time())
        state["duration"] = round(time.time() - t0, 1)
        scan_lock.release()


def scanner_loop():
    while True:
        scan_once()
        time.sleep(SCAN_INTERVAL)


# --------------------------------------------------------------------------
# Web-Server
# --------------------------------------------------------------------------


def api_events(qs):
    try:
        limit = max(1, min(int(qs.get("limit", ["300"])[0]), EVENT_KEEP))
    except ValueError:
        limit = 300
    kind = qs.get("kind", [""])[0]
    sql = ("SELECT e.*, d.name, d.unifi_name, d.hostname, d.ip, d.mac, d.vlan FROM events e "
           "LEFT JOIN devices d ON d.id = e.device")
    args = []
    if kind:
        sql += " WHERE e.kind = ?"
        args.append(kind)
    sql += " ORDER BY e.id DESC LIMIT ?"
    args.append(limit)
    with db_lock:
        rows = [dict(r) for r in db().execute(sql, args)]
        total = db().execute("SELECT COUNT(*) FROM events").fetchone()[0]
    return {"events": rows, "total": total}


def api_state():
    devs = list_devices()
    devs.sort(key=lambda d: ip_sort_key(d["ip"]))
    vlans = []
    for v in VLANS + [0]:
        ds = [d for d in devs if d["vlan"] == v]
        if v == 0 and not ds:
            continue
        vlans.append({"id": v, "label": vlan_label(v), "subnet": f"{SUBNET_PREFIX}.{v}.0/24" if v else "",
                      "total": len(ds), "online": sum(d["online"] for d in ds)})
    return {
        "devices": devs, "vlans": vlans,
        "tg_error": tg_state["last_error"], "tg_last_ok": tg_state["last_ok"], "notify_new": NOTIFY_NEW,
        "last_scan": state["last_scan"], "last_error": state["last_error"],
        "duration": state["duration"], "interval": SCAN_INTERVAL,
        "telegram": bool(TG_TOKEN and TG_CHAT), "mode": ONLINE_MODE,
        "unifi": unifi.enabled, "unifi_error": state["unifi_error"], "unifi_names": UNIFI_USE_NAMES,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "NetWatch"

    def log_message(self, fmt, *args):
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _auth(self):
        if not WEB_PASSWORD:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                if secrets.compare_digest(u, WEB_USER) and secrets.compare_digest(p, WEB_PASSWORD):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="NetWatch"')
        self.end_headers()
        return False

    def _send(self, code, body, ctype="application/json"):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except Exception:
            return {}

    def do_GET(self):
        if not self._auth():
            return
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            with open(os.path.join(HERE, "index.html"), encoding="utf-8") as f:
                return self._send(200, f.read(), "text/html")
        if path == "/api/state":
            return self._send(200, api_state())
        if path == "/api/events":
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return self._send(200, api_events(qs))
        if path == "/health":
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/scan":
            threading.Thread(target=scan_once, daemon=True).start()
            return self._send(200, {"ok": True})
        if path == "/api/telegram/test":
            ok, err = tg_send_now("✅ NetWatch Test-Nachricht – Telegram funktioniert.")
            add_event(None, "info", "Telegram-Test " + ("erfolgreich" if ok else "fehlgeschlagen"),
                      "sent" if ok else f"error: {err}")
            return self._send(200 if ok else 500, {"ok": ok, "error": err})
        if path.startswith("/api/devices/"):
            return self._update(path)
        self._send(404, {"error": "not found"})

    def _update(self, path):
        if path.endswith("/check"):
            try:
                dev_id = int(path.split("/")[3])
            except (ValueError, IndexError):
                return self._send(400, {"error": "bad id"})
            with db_lock:
                r = db().execute("SELECT ip FROM devices WHERE id=?", (dev_id,)).fetchone()
            if not r or not r["ip"]:
                return self._send(404, {"error": "not found"})
            return self._send(200, {"ok": True, "alive": ping(r["ip"]), "ip": r["ip"]})
        try:
            dev_id = int(path.rsplit("/", 1)[1])
        except ValueError:
            return self._send(400, {"error": "bad id"})
        data = self._body()
        fields = {}
        if "name" in data:
            fields["name"] = str(data["name"])[:80].strip()
        if "watch" in data:
            fields["watch"] = 1 if data["watch"] else 0
        if not fields:
            return self._send(400, {"error": "nothing to update"})
        with db_lock:
            sets = ",".join(f"{k}=?" for k in fields)
            db().execute(f"UPDATE devices SET {sets} WHERE id=?", (*fields.values(), dev_id))
            db().commit()
        self._send(200, {"ok": True})

    def do_DELETE(self):
        if not self._auth():
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/events":
            with db_lock:
                db().execute("DELETE FROM events")
                db().commit()
            return self._send(200, {"ok": True})
        if path.startswith("/api/devices/"):
            try:
                dev_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self._send(400, {"error": "bad id"})
            with db_lock:
                db().execute("DELETE FROM devices WHERE id=?", (dev_id,))
                db().commit()
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})


def main():
    db()
    if not OPN_KEY or not OPN_SECRET:
        log.warning("OPNSENSE_KEY / OPNSENSE_SECRET fehlen – Scans werden fehlschlagen.")
    threading.Thread(target=tg_worker, daemon=True).start()
    if TG_TOKEN and TG_CHAT:
        log.info("Telegram aktiv (Chat %s, neue Geräte melden: %s)", TG_CHAT, NOTIFY_NEW)
    else:
        log.warning("Telegram NICHT konfiguriert – TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID fehlen")
    threading.Thread(target=scanner_loop, daemon=True).start()
    if TG_TOKEN and TG_CHAT and TG_COMMANDS:
        threading.Thread(target=tg_bot_loop, daemon=True).start()
    log.info("NetWatch läuft auf Port %d (VLANs: %s)", WEB_PORT, ",".join(map(str, VLANS)))
    ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
