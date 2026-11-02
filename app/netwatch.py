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


def add_event(device_id, kind, text):
    with db_lock:
        db().execute("INSERT INTO events(ts,device,kind,text) VALUES(?,?,?,?)",
                     (int(time.time()), device_id, kind, text))
        db().execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)")
        db().commit()


# --------------------------------------------------------------------------
# Hilfsfunktionen
# --------------------------------------------------------------------------


def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if len(mac) == 17 else ""


def vlan_of(ip):
    """192.168.<vlan>.x -> vlan, sonst 0 (= 'Andere')."""
    try:
        ipaddress.IPv4Address(ip)
    except Exception:
        return None
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


def tg_api(method, payload, timeout=15):
    url = f"https://api.telegram.org/bot{TG_TOKEN}/{method}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def tg_send(text, chat_id=None):
    if not TG_TOKEN or not (chat_id or TG_CHAT):
        return False
    try:
        tg_api("sendMessage", {"chat_id": chat_id or TG_CHAT, "text": text,
                               "parse_mode": "HTML", "disable_web_page_preview": True})
        return True
    except Exception as e:
        log.warning("Telegram-Fehler: %s", e)
        return False


def esc(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def fmt_device(d):
    lines = [f"<b>{esc(display_name(d))}</b>"]
    if d.get("hostname") and d.get("hostname") != display_name(d):
        lines.append(f"Hostname: {esc(d['hostname'])}")
    lines.append(f"{esc(vlan_label(d['vlan']))} · {esc(d['ip'])}")
    lines.append(f"<code>{esc(d['mac'])}</code> {esc(d['vendor'])}".strip())
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
                tg_send(handle_command(text), chat)
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

        # Neue Geräte anlegen
        new_devices = []
        with db_lock:
            for key, info in seen.items():
                if key in known:
                    continue
                cur = db().execute(
                    "INSERT INTO devices(mac,vlan,ip,hostname,vendor,interface,unifi_name,conn,first_seen,"
                    "last_seen,online,fails,watch,changed_at) VALUES(?,?,?,?,?,?,?,?,?,?,0,0,?,?)",
                    (key[0], key[1], info["ip"], info["hostname"], info["vendor"], info["interface"],
                     info.get("unifi_name", ""), info.get("conn", ""),
                     now, None, 1 if WATCH_DEFAULT else 0, now))
                d = dict(db().execute("SELECT * FROM devices WHERE id=?", (cur.lastrowid,)).fetchone())
                known[key] = d
                new_devices.append(d)
            db().commit()

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
                if info and d["ip"] and info["ip"] != d["ip"]:
                    events.append(("ipchange", {**d, "old_ip": d["ip"], "ip": info["ip"]}))
                sets = ",".join(f"{k}=?" for k in fields)
                db().execute(f"UPDATE devices SET {sets} WHERE id=?", (*fields.values(), d["id"]))
            db().commit()

        # Benachrichtigungen
        for d in new_devices:
            add_event(d["id"], "new", f"Neues Gerät: {display_name(d)} ({d['ip']})")
            if NOTIFY_NEW:
                tg_send(fmt_new_device(d))
        for kind, d in events:
            if kind == "online":
                add_event(d["id"], kind, f"{display_name(d)} ist online")
                if d["watch"]:
                    tg_send("🟢 <b>Online</b>\n" + fmt_device(d))
            elif kind == "offline":
                add_event(d["id"], kind, f"{display_name(d)} ist offline")
                if d["watch"]:
                    tg_send("🔴 <b>Offline</b>\n" + fmt_device(d))
            elif kind == "ipchange":
                add_event(d["id"], kind, f"{display_name(d)}: IP {d['old_ip']} → {d['ip']}")
                if d["watch"]:
                    tg_send(f"🔁 <b>IP geändert</b> {esc(d['old_ip'])} → {esc(d['ip'])}\n" + fmt_device(d))

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
    with db_lock:
        evs = [dict(r) for r in db().execute("SELECT * FROM events ORDER BY id DESC LIMIT 50")]
    return {
        "devices": devs, "vlans": vlans, "events": evs,
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
            ok = tg_send("✅ NetWatch Test-Nachricht – Telegram funktioniert.")
            return self._send(200 if ok else 500, {"ok": ok})
        if path.startswith("/api/devices/"):
            return self._update(path)
        self._send(404, {"error": "not found"})

    def _update(self, path):
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
    threading.Thread(target=scanner_loop, daemon=True).start()
    if TG_TOKEN and TG_CHAT and TG_COMMANDS:
        threading.Thread(target=tg_bot_loop, daemon=True).start()
    log.info("NetWatch läuft auf Port %d (VLANs: %s)", WEB_PORT, ",".join(map(str, VLANS)))
    ThreadingHTTPServer(("0.0.0.0", WEB_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
