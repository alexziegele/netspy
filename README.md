# NetWatch – Geräteübersicht für OPNsense (+ UniFi) mit Telegram

Ein kleiner NetAlertX-Ersatz:

- liest ARP-Tabelle + DHCP-Leases (ISC, Kea oder Dnsmasq) aus der **OPNsense-API**
- optional verbundene Clients aus **UniFi OS** (Aliasname, SSID/AP oder Switch-Port, Signal)
- sortiert Geräte nach VLAN: `192.168.10.x` → VLAN 10 … `192.168.90.x` → VLAN 90
- Web-UI: Geräte benennen, Online-Status, Suche, Filter, Ereignisliste
- **Telegram**: Nachricht bei neuem Gerät (mit dem Namen, den das Gerät meldet), Online/Offline-Meldungen für markierte Geräte (🔔)
- **Telegram-Befehle**: `/check NAME`, `/online [vlan]`, `/offline [vlan]`, `/status`, `/scan`

Keine Abhängigkeiten außer Python – das Image ist sehr klein.

## 1. OPNsense-API-Schlüssel

1. *System → Zugang → Benutzer* → neuen Benutzer `netwatch` anlegen (kein Login nötig).
2. Rechte (*Effektive Rechte*) mindestens:
   - `Diagnostics: ARP Table`
   - je nach DHCP-Dienst: `Services: DHCP: Kea(v4)`, `Status: DHCP leases` (ISC) oder `Services: Dnsmasq DNS/DHCP`
3. Beim Benutzer unter *API-Schlüssel* auf **+** → Datei mit `key` und `secret` wird heruntergeladen.

## 2. UniFi (optional)

Im UniFi-Controller einen **lokalen** Benutzer anlegen (*Admins & Users* → Admin hinzufügen → „Restrict to local access only“, Rolle *View Only* reicht).
UDM / Cloud Key Gen2+ / UniFi OS Server: `UNIFI_IS_UNIFI_OS=true`. Klassischer Controller (Port 8443): `false`.

Vorteil: Handys im WLAN antworten oft nicht auf Ping – UniFi weiß trotzdem, dass sie verbunden sind.

## 3. Telegram-Bot

1. In Telegram **@BotFather** → `/newbot` → Token kopieren.
2. Dem neuen Bot einmal eine Nachricht schicken.
3. Chat-ID holen: `https://api.telegram.org/bot<TOKEN>/getUpdates` im Browser öffnen → `"chat":{"id":123456789…}`.
   (Für eine Gruppe: Bot zur Gruppe hinzufügen, die ID beginnt dann mit `-`.)

Der Bot reagiert nur auf Nachrichten aus dieser Chat-ID.

## 4. Starten

```bash
cp .env.example .env     # Werte eintragen
docker compose up -d --build
```

Web-UI: `http://<docker-host>:8080`

## Online-Erkennung

Ein Gerät gilt als online, wenn es **auf Ping antwortet**, **in der ARP-Tabelle aktiv ist** oder **in UniFi verbunden ist** (`ONLINE_MODE=ping_or_arp`).
Offline wird erst nach `OFFLINE_AFTER_CHECKS` Fehlversuchen gemeldet (verhindert Fehlalarme).

Hinweise:

- Der Container läuft im `host`-Netz und pingt von dort in alle VLANs. Die **Firewall-Regeln** müssen ICMP vom Docker-Host in die anderen VLANs erlauben.
- OPNsense hält ARP-Einträge standardmäßig 20 Minuten. Für schnellere Offline-Erkennung unter *System → Einstellungen → Tunables* `net.link.ether.inet.max_age` z. B. auf `300` setzen.
- `/check NAME` pingt das Gerät **live**. 🟡 heißt: kein Ping, aber Firewall/UniFi sieht es noch.

## Wie Geräte gespeichert werden

Ein Gerät ist **MAC + VLAN**. Wechselt die IP per DHCP, bleibt der Name erhalten (bei markierten Geräten kommt eine Telegram-Meldung „IP geändert“).
Geräte mit **zufälliger MAC-Adresse** (iOS/Android „Private Adresse“) tauchen nach einem Wechsel als neues Gerät auf – für eigene Geräte im WLAN die private Adresse am besten ausschalten.

Daten liegen in `./data/netwatch.db` (SQLite).

## Alle Einstellungen

| Variable | Standard | Bedeutung |
|---|---|---|
| `OPNSENSE_URL` | `https://192.168.10.1` | Adresse der OPNsense |
| `OPNSENSE_KEY` / `OPNSENSE_SECRET` | – | API-Zugang |
| `OPNSENSE_VERIFY_SSL` | `false` | Zertifikat prüfen |
| `SUBNET_PREFIX` | `192.168` | erste zwei Oktette |
| `VLANS` | `10,20,…,90` | drittes Oktett = VLAN |
| `VLAN_NAMES` | – | z. B. `10:Management,40:IoT` |
| `SCAN_INTERVAL` | `60` | Sekunden zwischen Scans |
| `ONLINE_MODE` | `ping_or_arp` | `ping_or_arp`, `ping` oder `arp` (UniFi zählt immer zusätzlich) |
| `OFFLINE_AFTER_CHECKS` | `3` | Fehlversuche bis offline |
| `INCLUDE_FIREWALL` | `false` | eigene Interfaces der OPNsense anzeigen |
| `UNIFI_URL` | – | z. B. `https://192.168.10.2` (leer = aus) |
| `UNIFI_USER` / `UNIFI_PASSWORD` | – | lokaler UniFi-Benutzer |
| `UNIFI_SITE` | `default` | Site-ID |
| `UNIFI_IS_UNIFI_OS` | `true` | UniFi OS oder klassischer Controller |
| `UNIFI_USE_NAMES` | `true` | Aliasnamen aus UniFi als Anzeigename |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | – | Telegram |
| `NOTIFY_NEW_DEVICES` | `true` | Meldung bei neuem Gerät |
| `WATCH_NEW_DEVICES` | `false` | neue Geräte automatisch 🔔 beobachten |
| `TELEGRAM_COMMANDS` | `true` | Bot-Befehle aktivieren |
| `WEB_PORT` | `8080` | Port des Web-UI |
| `WEB_USER` / `WEB_PASSWORD` | `admin` / leer | Login fürs Web-UI (leer = ohne) |
