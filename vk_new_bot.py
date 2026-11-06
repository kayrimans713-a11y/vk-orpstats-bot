"""
VK-бот мониторинга SA-MP сервера ONLINE RP HAWAII — версия 5.9.1.

Новое в 5.9.1:
  * Полное игнорирование пользователей без доступа (бот не отвечает даже на /start).
  * Админы бота и основатель имеют доступ автоматически.
  * Убран хардкод токена (только через переменные окружения).
"""

import json
import logging
import os
import re
import secrets
import socket
import sqlite3
import struct
import threading
import time
from datetime import datetime, timedelta, timezone

import vk_api
from vk_api.bot_longpoll import VkBotEventType, VkBotLongPoll
from vk_api.keyboard import VkKeyboard, VkKeyboardColor
from vk_api.utils import get_random_id

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.dates as mdates
    import matplotlib.pyplot as plt
    HAVE_MPL = True
except Exception:
    HAVE_MPL = False

# ───────────────────────── НАСТРОЙКИ ─────────────────────────
# Токен теперь берется ТОЛЬКО из переменных окружения (без хардкода)
VK_TOKEN = os.getenv("VK_TOKEN") 
GROUP_ID = int(os.getenv("VK_GROUP_ID"))
ADMIN_VK_ID = int(os.getenv("VK_ADMIN_ID"))

SERVER_NAME = "ONLINE RP HAWAII"
SERVER_HOST = "s4.gta-mobile.ru"
SERVER_IP = "95.213.255.224"
SERVER_PORT = 7777
POLL_INTERVAL = 15
QUERY_TIMEOUT = 3
FAILS_TO_OFFLINE = 3
DB_PATH = "vk_bot.db"
TZ = timezone(timedelta(hours=3))
DAY_START_HOUR = 5

MAX_TRACKS = 20
CHAT_MAX_TRACKS = 10
REARM_GAP = 3
STATS_HOURS = 48
CHART_CACHE_SEC = 180
CHART_PATH = "online_chart.png"
AUTO_INTERVAL = 30 * 60
PROFILE_DAYS = 7

ADMINS = """
Nathan_Morris Veronika_Lavanda Anna_Orlova Laurent_Sykes Steven_Macalister
Rocky_Rockstar Shay_Cormac Itan_Yonkers Weka_Hewarc Chara_Dreemurr
Egor_Talavera Clayton_Corleone Pavel_Nakozin Zein_Carlyle Cameron_Flores
Kyle_Carlyle Homelander_Quattroki Sasha_Ilumetrezzix Leon_Burbery
Pioneer_Squirtezzer Angel_Gonzalez Sebastian_Nekrasov Charles_Henderson Matthew_Sykes Billy_Russo Hawaii_Bot
""".split()
ADMINS_LOWER = {a.lower(): a for a in ADMINS}

SPECIAL_ADMINS = {
    "sebastian_nekrasov", "charles_henderson", "nathan_morris", 
    "veronika_lavanda", "anna_orlova", "laurent_sykes", "steven_macalister"
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vkbot")
START_TS = time.time()
NICK_RE = re.compile(r"^[A-Za-z0-9_\[\]\(\)\$@\.=]{2,24}$")

# ───────────────────────── SA-MP QUERY ───────────────────────
def _packet(opcode: bytes) -> bytes:
    return (b"SAMP" + bytes(int(x) for x in SERVER_IP.split("."))
            + struct.pack("<H", SERVER_PORT) + opcode)

def _ask(sock: socket.socket, opcode: bytes) -> bytes:
    pkt = _packet(opcode)
    for _ in range(2):
        sock.sendto(pkt, (SERVER_IP, SERVER_PORT))
        try:
            while True:
                data, _addr = sock.recvfrom(8192)
                if data[:4] == b"SAMP" and data[10:11] == opcode:
                    return data
        except socket.timeout:
            continue
    raise TimeoutError("no response")

def query_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(QUERY_TIMEOUT)
    try:
        d = _ask(sock, b"i")
        online, maxp = struct.unpack_from("<HH", d, 12)
        info = {"online": online, "max": maxp, "passworded": bool(d[11]),
                "hostname": "", "gamemode": "", "language": "", "rules": {}}
        try:
            off, strs = 16, []
            for _ in range(3):
                (ln,) = struct.unpack_from("<I", d, off)
                strs.append(d[off + 4: off + 4 + ln].decode("cp1251", "replace"))
                off += 4 + ln
            info["hostname"], info["gamemode"], info["language"] = strs
        except (struct.error, IndexError):
            pass
        try:
            r = _ask(sock, b"r")
            (rc,) = struct.unpack_from("<H", r, 11)
            off = 13
            for _ in range(rc):
                nl = r[off]
                rn = r[off + 1: off + 1 + nl].decode("cp1251", "replace")
                off += 1 + nl
                vl = r[off]
                rv = r[off + 1: off + 1 + vl].decode("cp1251", "replace")
                off += 1 + vl
                info["rules"][rn.lower()] = rv
        except (TimeoutError, struct.error, IndexError):
            pass

        players = None
        try:
            d = _ask(sock, b"d")
            (cnt,) = struct.unpack_from("<H", d, 11)
            off, players = 13, []
            for _ in range(cnt):
                pid = d[off]
                nl = d[off + 1]
                name = d[off + 2: off + 2 + nl].decode("cp1251", "replace")
                off += 2 + nl
                score, ping = struct.unpack_from("<iI", d, off)
                off += 8
                players.append({"id": pid, "name": name, "score": score, "ping": ping})
            if online > 0 and not players:
                players = None
        except (TimeoutError, struct.error, IndexError):
            players = None
        return info, players
    finally:
        sock.close()

# ───────────────────────── БАЗА ДАННЫХ ───────────────────────
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_lock = threading.Lock()
_db.executescript("""
CREATE TABLE IF NOT EXISTS users(
    user_id INTEGER PRIMARY KEY, first_seen INTEGER, last_seen INTEGER, requests INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS allowed_users(
    user_id INTEGER PRIMARY KEY, added_by INTEGER, added_at INTEGER);
CREATE TABLE IF NOT EXISTS blocked(user_id INTEGER PRIMARY KEY, blocked_at INTEGER);
CREATE TABLE IF NOT EXISTS players(
    name_lower TEXT PRIMARY KEY, name TEXT, online INTEGER DEFAULT 0,
    last_join INTEGER, last_leave INTEGER, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS history(ts INTEGER, online INTEGER, admins INTEGER);
CREATE INDEX IF NOT EXISTS idx_hist ON history(ts);
CREATE TABLE IF NOT EXISTS tracks(
    user_id INTEGER, name_lower TEXT, name TEXT, added_at INTEGER,
    PRIMARY KEY(user_id, name_lower));
CREATE TABLE IF NOT EXISTS online_tracks(
    user_id INTEGER, threshold INTEGER, armed INTEGER DEFAULT 1,
    PRIMARY KEY(user_id, threshold));
CREATE TABLE IF NOT EXISTS event_tracks(user_id INTEGER, kind TEXT, PRIMARY KEY(user_id, kind));
CREATE TABLE IF NOT EXISTS sessions(name_lower TEXT, join_ts INTEGER, leave_ts INTEGER);
CREATE INDEX IF NOT EXISTS idx_sess ON sessions(name_lower, join_ts);
CREATE TABLE IF NOT EXISTS bot_admins(user_id INTEGER PRIMARY KEY, added_by INTEGER, added_at INTEGER);
CREATE TABLE IF NOT EXISTS auto_notify(user_id INTEGER PRIMARY KEY, last_sent INTEGER);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS chat_admins(peer_id INTEGER PRIMARY KEY, user_id INTEGER, added_at INTEGER);
CREATE TABLE IF NOT EXISTS chat_settings(
    peer_id INTEGER PRIMARY KEY, tracks INTEGER DEFAULT 1,
    down INTEGER DEFAULT 1, up INTEGER DEFAULT 1, title TEXT);
CREATE TABLE IF NOT EXISTS chat_tracks(
    peer_id INTEGER, kind TEXT, value TEXT, added_by INTEGER, added_at INTEGER,
    PRIMARY KEY(peer_id, kind, value));
CREATE TABLE IF NOT EXISTS admin_ranks(name_lower TEXT PRIMARY KEY, rank TEXT);
""")
for _sql in ("ALTER TABLE users ADD COLUMN nick TEXT", "ALTER TABLE players ADD COLUMN score INTEGER"):
    try:
        _db.execute(_sql)
    except sqlite3.OperationalError:
        pass
try:
    _db.execute("ALTER TABLE chat_settings ADD COLUMN title TEXT")
except sqlite3.OperationalError:
    pass

_db.execute("INSERT INTO sessions SELECT name_lower, COALESCE(last_join, last_seen), NULL FROM players "
            "WHERE online=1 AND name_lower NOT IN (SELECT name_lower FROM sessions WHERE leave_ts IS NULL)")
_db.commit()

def db_exec(sql, args=()):
    with _lock:
        cur = _db.execute(sql, args)
        _db.commit()
        return cur.rowcount

def db_one(sql, args=()):
    with _lock:
        return _db.execute(sql, args).fetchone()

def db_all(sql, args=()):
    with _lock:
        return _db.execute(sql, args).fetchall()

def kv_get(k):
    r = db_one("SELECT v FROM kv WHERE k=?", (k,))
    return r[0] if r else None

def kv_set(k, v):
    db_exec("INSERT INTO kv VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=?", (k, str(v), str(v)))

state = {"up": None, "info": None, "players": None, "last_ok": None, "fails": 0, "since": None}

def now() -> int:
    return int(time.time())

def fmt_dt(ts) -> str:
    return datetime.fromtimestamp(ts, TZ).strftime("%d.%m.%Y %H:%M:%S")

def fmt_hm(ts) -> str:
    return datetime.fromtimestamp(ts, TZ).strftime("%H:%M")

def fmt_dur(sec) -> str:
    sec = max(0, int(sec))
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    parts = []
    if d: parts.append(f"{d} д")
    if h: parts.append(f"{h} ч")
    if m: parts.append(f"{m} мин")
    if not parts: parts.append(f"{s} сек")
    return " ".join(parts[:2])

def ago(ts) -> str:
    d = now() - ts
    return "только что" if d < 30 else f"{fmt_dur(d)} назад"

def day_start_ts(t=None) -> int:
    dt = datetime.fromtimestamp(t or now(), TZ)
    start = dt.replace(hour=DAY_START_HOUR, minute=0, second=0, microsecond=0)
    if dt < start:
        start -= timedelta(days=1)
    return int(start.timestamp())

if kv_get("monitor_since") is None:
    first = db_one("SELECT MIN(ts) FROM history")
    kv_set("monitor_since", (first[0] if first and first[0] else now()))

# ───────────────────────── РОЛИ И ДОСТУП ─────────────────────
def is_owner(uid: int) -> bool:
    return ADMIN_VK_ID != 0 and uid == ADMIN_VK_ID

def is_staff(uid: int) -> bool:
    return is_owner(uid) or bool(db_one("SELECT 1 FROM bot_admins WHERE user_id=?", (uid,)))

def has_access(uid: int) -> bool:
    if is_owner(uid) or is_staff(uid):
        return True
    return bool(db_one("SELECT 1 FROM allowed_users WHERE user_id=?", (uid,)))

def chat_admin_of(peer_id: int):
    r = db_one("SELECT user_id FROM chat_admins WHERE peer_id=?", (peer_id,))
    return r[0] if r else None

def is_chat_admin(uid: int, peer_id: int) -> bool:
    if is_owner(uid):
        return True
    return chat_admin_of(peer_id) == uid

def chat_ensure(peer_id: int, title: str = None):
    if peer_id < 2_000_000_000:
        return
    db_exec("INSERT OR IGNORE INTO chat_settings(peer_id) VALUES(?)", (peer_id,))
    if title:
        db_exec("UPDATE chat_settings SET title=? WHERE peer_id=?", (title[:60], peer_id))

def chat_cfg(peer_id: int) -> dict:
    r = db_one("SELECT tracks, down, up FROM chat_settings WHERE peer_id=?", (peer_id,))
    if not r:
        return {"tracks": 1, "down": 1, "up": 1}
    return {"tracks": r[0], "down": r[1], "up": r[2]}

def chat_cfg_set(peer_id: int, key: str, val: int):
    db_exec(f"UPDATE chat_settings SET {key}=? WHERE peer_id=?", (val, peer_id))

def all_chat_peers() -> list:
    return [r[0] for r in db_all("SELECT peer_id FROM chat_settings")]

def rank_of(name: str) -> str:
    r = db_one("SELECT rank FROM admin_ranks WHERE name_lower=?", (name.lower(),))
    return r[0] if r else ""

# ───────────────────────── VK API ────────────────────────────
vk_session = vk_api.VkApi(token=VK_TOKEN)
vk = vk_session.get_api()
upload = vk_api.VkUpload(vk_session)
_vk_lock = threading.Lock()

def _build_kb(staff: bool) -> str:
    kb = VkKeyboard(one_time=False, inline=False)
    kb.add_button("Сервер", color=VkKeyboardColor.PRIMARY, payload={"cmd": "server"})
    kb.add_button("Игроки", color=VkKeyboardColor.PRIMARY, payload={"cmd": "players"})
    kb.add_line()
    kb.add_button("Профиль", color=VkKeyboardColor.SECONDARY, payload={"cmd": "profile"})
    kb.add_button("Трекер", color=VkKeyboardColor.POSITIVE, payload={"cmd": "tracklist"})
    if staff:
        kb.add_line()
        kb.add_button("Админы", color=VkKeyboardColor.PRIMARY, payload={"cmd": "admins"})
        kb.add_button("Автоотчёт", color=VkKeyboardColor.SECONDARY, payload={"cmd": "auto"})
    return kb.get_keyboard()

KB_USER = _build_kb(False)
KB_STAFF = _build_kb(True)

def kb_for(uid: int) -> str:
    return KB_STAFF if is_staff(uid) else KB_USER

def send(peer_id: int, text: str, keyboard: str = None, attachment: str = None):
    params = dict(peer_id=peer_id, message=text[:4000], random_id=get_random_id())
    
    if peer_id < 2_000_000_000:
        if keyboard:
            params["keyboard"] = keyboard
        elif keyboard != "":
            params["keyboard"] = kb_for(peer_id)
            
    if attachment:
        params["attachment"] = attachment
    try:
        with _vk_lock:
            vk.messages.send(**params)
    except Exception as e:
        if attachment:
            log.warning("Не удалось отправить с вложением (%s), повтор без него", e)
            return send(peer_id, text, keyboard)
        log.error("Не удалось отправить сообщение %s: %s", peer_id, e)

def send_long(peer_id: int, text: str):
    chunk, size = [], 0
    for line in text.split("\n"):
        if size + len(line) + 1 > 3500 and chunk:
            send(peer_id, "\n".join(chunk))
            chunk, size = [], 0
        chunk.append(line)
        size += len(line) + 1
    if chunk:
        send(peer_id, "\n".join(chunk))

def notify(uid: int, text: str):
    send(uid, text)
    time.sleep(0.05)

def notify_event(kind: str, text: str):
    for (uid,) in db_all("SELECT user_id FROM event_tracks WHERE kind=?", (kind,)):
        notify(uid, text)
    for peer in all_chat_peers():
        cfg = chat_cfg(peer)
        if not cfg.get("tracks"):
            continue
        if kind in ("down", "up") and not cfg.get(kind):
            continue
        if not db_one("SELECT 1 FROM chat_tracks WHERE peer_id=? AND kind=?", (peer, kind)):
            continue
        send(peer, text)

# ───────────────────────── МОНИТОРИНГ ────────────────────────
def apply_players(players):
    t = now()
    current = {p["name"].lower(): p for p in players}
    joined, left = [], []
    with _lock:
        cur = _db.cursor()
        was = {r[0]: (r[1], r[2]) for r in cur.execute(
            "SELECT name_lower, name, last_join FROM players WHERE online=1")}
        for low, p in current.items():
            if low in was:
                cur.execute("UPDATE players SET last_seen=?, name=?, score=? WHERE name_lower=?",
                            (t, p["name"], p["score"], low))
            else:
                joined.append(p["name"])
                cur.execute(
                    "INSERT INTO players(name_lower,name,online,last_join,last_seen,score) VALUES(?,?,1,?,?,?) "
                    "ON CONFLICT(name_lower) DO UPDATE SET online=1,last_join=?,last_seen=?,name=?,score=?",
                    (low, p["name"], t, t, p["score"], t, t, p["name"], p["score"]))
                cur.execute("INSERT INTO sessions VALUES(?,?,NULL)", (low, t))
        for low, (name, last_join) in was.items():
            if low not in current:
                left.append((name, last_join, t))
                cur.execute("UPDATE players SET online=0, last_leave=? WHERE name_lower=?", (t, low))
                cur.execute("UPDATE sessions SET leave_ts=? WHERE name_lower=? AND leave_ts IS NULL", (t, low))
        _db.commit()
    return joined, left

def notify_players(joined, left, online):
    t = now()
    for name in joined:
        for (uid,) in db_all("SELECT user_id FROM tracks WHERE name_lower=?", (name.lower(),)):
            notify(uid, f"🟢 {name} зашёл на сервер\nВремя: {fmt_dt(t)} (МСК)\nОнлайн сервера: {online}")
        for peer in all_chat_peers():
            if chat_cfg(peer).get("tracks") and db_one(
                    "SELECT 1 FROM chat_tracks WHERE peer_id=? AND kind='player' AND value=?",
                    (peer, name.lower())):
                send(peer, f"🟢 {name} зашёл на сервер\nВремя: {fmt_dt(t)} (МСК)\nОнлайн сервера: {online}")
    for name, last_join, lt in left:
        for (uid,) in db_all("SELECT user_id FROM tracks WHERE name_lower=?", (name.lower(),)):
            dur = f"\nБыл в сети: {fmt_dur(lt - last_join)}" if last_join else ""
            notify(uid, f"⚫ {name} вышел с сервера\nВремя: {fmt_dt(lt)} (МСК){dur}\nОнлайн сервера: {online}")
        for peer in all_chat_peers():
            if chat_cfg(peer).get("tracks") and db_one(
                    "SELECT 1 FROM chat_tracks WHERE peer_id=? AND kind='player' AND value=?",
                    (peer, name.lower())):
                dur = f"\nБыл в сети: {fmt_dur(lt - last_join)}" if last_join else ""
                send(peer, f"⚫ {name} вышел с сервера\nВремя: {fmt_dt(lt)} (МСК){dur}\nОнлайн сервера: {online}")

def check_online_thresholds(online):
    for uid, th, armed in db_all("SELECT user_id, threshold, armed FROM online_tracks"):
        if armed and online >= th:
            db_exec("UPDATE online_tracks SET armed=0 WHERE user_id=? AND threshold=?", (uid, th))
            notify(uid, f"📈 Онлайн сервера достиг {th}!\nСейчас в сети: {online}")
        elif not armed and online <= max(0, th - REARM_GAP):
            db_exec("UPDATE online_tracks SET armed=1 WHERE user_id=? AND threshold=?", (uid, th))
    
    for peer, th in db_all("SELECT peer_id, value FROM chat_tracks WHERE kind='online'"):
        try: th = int(th)
        except ValueError: continue
        key = f"chat_armed_{peer}_{th}"
        a = kv_get(key)
        a = int(a) if a is not None else 1
        if a and online >= th:
            kv_set(key, 0)
            if chat_cfg(peer).get("tracks"): send(peer, f"📈 Онлайн сервера достиг {th}!\nСейчас в сети: {online}")
        elif not a and online <= max(0, th - REARM_GAP):
            kv_set(key, 1)

    for peer, th in db_all("SELECT peer_id, value FROM chat_tracks WHERE kind='online_fall'"):
        try: th = int(th)
        except ValueError: continue
        key = f"chat_armed_fall_{peer}_{th}"
        a = kv_get(key)
        a = int(a) if a is not None else 1
        if a and online <= th:
            kv_set(key, 0)
            if chat_cfg(peer).get("tracks"): send(peer, f"📉 Онлайн сервера упал до {th}!\nСейчас в сети: {online}")
        elif not a and online >= th + REARM_GAP:
            kv_set(key, 1)

def check_mod_change(info):
    sig = f"{info.get('gamemode', '')} | {info.get('rules', {}).get('version', '')}"
    if sig.strip(" |") == "":
        return
    old = kv_get("mod_sig")
    if old != sig:
        kv_set("mod_sig", sig)
        if old is not None:
            notify_event("mod", f"📝 Обновление мода на сервере\nБыло: {old}\nСтало: {sig}")

def monitor_loop():
    prune_at = 0
    while True:
        try:
            info, players = query_server()
        except Exception as e:
            state["fails"] += 1
            log.warning("Опрос не удался (%s): %s", state["fails"], e)
            if state["fails"] >= FAILS_TO_OFFLINE and state["up"] is not False:
                was_up = state["up"] is True
                state.update(up=False, players=None, since=now())
                if was_up:
                    try:
                        notify_event("down", f"🔴 Сервер {SERVER_NAME} недоступен\nВремя: {fmt_dt(now())} (МСК)")
                    except Exception:
                        log.exception("Ошибка уведомления о падении")
            time.sleep(POLL_INTERVAL)
            continue

        try:
            was_down = state["up"] is False
            first_ok = state["last_ok"] is None
            can_notify = state["up"] is True and state["players"] is not None
            down_since = state["since"]
            if not state["up"]:
                state["since"] = now()
            state.update(up=True, info=info, players=players, last_ok=now(), fails=0)

            if was_down and down_since:
                notify_event("up", f"🟢 Сервер {SERVER_NAME} снова доступен\n"
                                   f"Был недоступен: {fmt_dur(now() - down_since)}\nОнлайн: {info['online']}")
            
            if players is not None:
                joined, left = apply_players(players)
                if can_notify and not first_ok:
                    notify_players(joined, left, info["online"])
                    
            adm = sum(1 for p in (players or []) if p["name"].lower() in ADMINS_LOWER)
            db_exec("INSERT INTO history VALUES(?,?,?)", (now(), info["online"], adm))
            check_online_thresholds(info["online"])
            check_mod_change(info)
            if now() - prune_at > 3600:
                prune_at = now()
                db_exec("DELETE FROM history WHERE ts < ?", (now() - 3 * 86400,))
                db_exec("DELETE FROM sessions WHERE leave_ts IS NOT NULL AND leave_ts < ?", (now() - 30 * 86400,))
        except Exception:
            log.exception("Ошибка в цикле мониторинга")
        time.sleep(POLL_INTERVAL)

# ───────────────────────── ГРАФИК ────────────────────────────
_chart = {"ts": 0, "att": None}
_chart_lock = threading.Lock()

def chart_attachment():
    if not HAVE_MPL:
        return None
    with _chart_lock:
        if _chart["att"] and now() - _chart["ts"] < CHART_CACHE_SEC:
            return _chart["att"]
        try:
            rows = db_all("SELECT ts, online FROM history WHERE ts >= ? ORDER BY ts",
                          (now() - STATS_HOURS * 3600,))
            if len(rows) < 3:
                return None
            xs = [datetime.fromtimestamp(t, TZ) for t, _ in rows]
            ys = [o for _, o in rows]
            bg = "#1b2330"
            fig, ax = plt.subplots(figsize=(9, 3.4), dpi=110)
            fig.patch.set_facecolor(bg)
            ax.set_facecolor(bg)
            ax.plot(xs, ys, color="#4f8fe8", linewidth=1.4)
            ax.fill_between(xs, ys, color="#4f8fe8", alpha=0.15)
            ax.set_ylim(bottom=0)
            ax.xaxis.set_major_locator(mdates.HourLocator(byhour=[0, 6, 12, 18], tz=TZ))
            ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M", tz=TZ))
            ax.tick_params(colors="#9aa7b8", labelsize=8)
            for s in ax.spines.values():
                s.set_visible(False)
            ax.grid(color="#2c3849", linewidth=0.6)
            ax.set_title(f"Онлайн за {STATS_HOURS} ч (МСК)", color="#d7e0ec", fontsize=10)
            fig.tight_layout()
            fig.savefig(CHART_PATH, facecolor=bg)
            plt.close(fig)
            with _vk_lock:
                photo = upload.photo_messages(CHART_PATH)[0]
            att = f"photo{photo['owner_id']}_{photo['id']}"
            if photo.get("access_key"):
                att += f"_{photo['access_key']}"
            _chart.update(ts=now(), att=att)
            return att
        except Exception as e:
            log.warning("График не создан/не загружен: %s", e)
            return None

# ───────────────────────── ТРЕКЕРЫ (ЛИЧКА) ──────────────────
def tracker_count(uid: int) -> int:
    return sum((db_one(f"SELECT COUNT(*) FROM {t} WHERE user_id=?", (uid,)) or [0])[0]
               for t in ("tracks", "online_tracks", "event_tracks"))

def is_tracked(uid: int, name: str) -> bool:
    return bool(db_one("SELECT 1 FROM tracks WHERE user_id=? AND name_lower=?", (uid, name.lower())))

def cmd_track(uid: int, arg: str) -> str:
    nick = arg.strip().replace(" ", "_")
    if not NICK_RE.match(nick):
        return "Укажи ник игрока, например: /track Laurent_Sykes"
    row = db_one("SELECT name, online FROM players WHERE name_lower=?", (nick.lower(),))
    name = row[0] if row else nick
    if is_tracked(uid, name):
        return f"Ты уже следишь за {name}."
    if tracker_count(uid) >= MAX_TRACKS:
        return f"Лимит трекеров — {MAX_TRACKS}. Убери ненужные: /tracklist."
    db_exec("INSERT OR IGNORE INTO tracks VALUES(?,?,?,?)", (uid, name.lower(), name, now()))
    status = ""
    if row:
        status = "\nСейчас: 🟢 в сети" if row[1] else "\nСейчас: ⚫ не в сети"
    return (f"🔔 Слежу за {name}. Напишу в личку, когда он зайдёт или выйдет.{status}\n"
            "Уведомления приходят, только если ты разрешил сообщения от сообщества.")

def cmd_untrack(uid: int, arg: str) -> str:
    nick = arg.strip().replace(" ", "_").lower()
    if not nick:
        return "Использование: /untrack ник"
    n = db_exec("DELETE FROM tracks WHERE user_id=? AND name_lower=?", (uid, nick))
    return f"🔕 Больше не слежу за {arg.strip()}." if n else "Ты не следил за этим игроком."

def add_online_track(uid: int, th: int) -> str:
    if db_one("SELECT 1 FROM online_tracks WHERE user_id=? AND threshold=?", (uid, th)):
        return f"Порог {th} уже стоит."
    if tracker_count(uid) >= MAX_TRACKS:
        return f"Лимит трекеров — {MAX_TRACKS}. Убери ненужные: /tracklist."
    cur_online = (state["info"] or {}).get("online") if state["up"] else None
    armed = 0 if (cur_online is not None and cur_online >= th) else 1
    db_exec("INSERT INTO online_tracks VALUES(?,?,?)", (uid, th, armed))
    msg = f"🔔 Напишу, когда онлайн сервера достигнет {th}."
    if not armed:
        msg += (f"\nСейчас онлайн уже {cur_online}, поэтому уведомление придёт, "
                f"когда он упадёт до {max(0, th - REARM_GAP)} и снова поднимется до {th}.")
    return msg

def cmd_trackonline(uid: int, arg: str) -> str:
    if not arg.strip().isdigit() or not (1 <= int(arg) <= 1000):
        return "Укажи число от 1 до 1000, например: /trackonline 50"
    return add_online_track(uid, int(arg))

def cmd_untrackonline(uid: int, arg: str) -> str:
    if not arg.strip().isdigit():
        return "Использование: /untrackonline число"
    n = db_exec("DELETE FROM online_tracks WHERE user_id=? AND threshold=?", (uid, int(arg)))
    return f"🔕 Порог {int(arg)} убран." if n else "Такого порога у тебя нет."

EVENT_LABELS = {"mod": "📝 Обновление мода", "down": "🔴 Падение сервера", "up": "🟢 Восстановление"}

def toggle_tracker(uid: int, pl: dict) -> str:
    kind = pl.get("k")
    if kind == "online":
        th = int(pl.get("n", 0))
        if db_one("SELECT 1 FROM online_tracks WHERE user_id=? AND threshold=?", (uid, th)):
            db_exec("DELETE FROM online_tracks WHERE user_id=? AND threshold=?", (uid, th))
            return f"🔕 Порог онлайна {th} выключен."
        return add_online_track(uid, th)
    if kind in EVENT_LABELS:
        if db_one("SELECT 1 FROM event_tracks WHERE user_id=? AND kind=?", (uid, kind)):
            db_exec("DELETE FROM event_tracks WHERE user_id=? AND kind=?", (uid, kind))
            return f"🔕 Выключено: {EVENT_LABELS[kind]}."
        if tracker_count(uid) >= MAX_TRACKS:
            return f"Лимит трекеров — {MAX_TRACKS}. Убери ненужные: /tracklist."
        db_exec("INSERT OR IGNORE INTO event_tracks VALUES(?,?)", (uid, kind))
        return f"🔔 Включено: {EVENT_LABELS[kind]}. Напишу в личку."
    return "Неизвестный трекер."

def cmd_tracklist(uid: int) -> str:
    players = db_all("SELECT t.name, p.online FROM tracks t "
                     "LEFT JOIN players p ON p.name_lower = t.name_lower "
                     "WHERE t.user_id=? ORDER BY t.name", (uid,))
    ths = db_all("SELECT threshold FROM online_tracks WHERE user_id=? ORDER BY threshold", (uid,))
    evs = db_all("SELECT kind FROM event_tracks WHERE user_id=?", (uid,))
    if not (players or ths or evs):
        return ("🔔 Трекер пуст.\n\n"
                "/track ник — следить за игроком\n"
                "/trackonline число — порог онлайна сервера\n"
                "Кнопки событий и порогов — под командой /server.\n"
                "Или напиши ник игрока и нажми «Следить».")
    lines = [f"🔔 Твой трекер ({tracker_count(uid)}/{MAX_TRACKS})\n"]
    if players:
        lines.append("Игроки:")
        lines += [f"{'🟢' if online else '⚫'} {name}" for name, online in players]
    if ths:
        lines.append("\nПороги онлайна: " + ", ".join(str(t[0]) for t in ths))
    if evs:
        lines.append("События: " + ", ".join(EVENT_LABELS.get(k[0], k[0]) for k in evs))
    lines.append("\nУбрать: /untrack ник, /untrackonline число, кнопки в /server")
    return "\n".join(lines)

def server_kb(uid: int) -> str:
    return None

CHAT_EVENTS = ("down", "up", "mod")

def chat_track_count(peer: int) -> int:
    return (db_one("SELECT COUNT(*) FROM chat_tracks WHERE peer_id=?", (peer,)) or [0])[0]

def chat_add_track(peer: int, kind: str, value: str, by: int) -> str:
    if chat_track_count(peer) >= CHAT_MAX_TRACKS:
        return f"Лимит трекеров беседы — {CHAT_MAX_TRACKS}. Убери ненужные: /tracklist."
    if db_one("SELECT 1 FROM chat_tracks WHERE peer_id=? AND kind=? AND value=?", (peer, kind, value)):
        return "Такой трекер уже есть."
    db_exec("INSERT INTO chat_tracks VALUES(?,?,?,?,?)", (peer, kind, value, by, now()))
    if kind == "online":
        kv_set(f"chat_armed_{peer}_{value}", 1)
    if kind == "online_fall":
        kv_set(f"chat_armed_fall_{peer}_{value}", 1)
    if kind == "player":
        row = db_one("SELECT name, online FROM players WHERE name_lower=?", (value.lower(),))
        name = row[0] if row else value
        return f"🔔 Беседа следит за {name}."
    if kind == "online":
        return f"🔔 Беседа следит за онлайном ≥ {value}."
    if kind == "online_fall":
        return f"🔔 Беседа следит за падением онлайна до {value}."
    return f"🔔 Беседа подписана: {EVENT_LABELS.get(kind, kind)}."

def chat_del_track(peer: int, kind: str, value: str) -> str:
    n = db_exec("DELETE FROM chat_tracks WHERE peer_id=? AND kind=? AND value=?", (peer, kind, value))
    return "🔕 Трекер убран." if n else "Такого трекера нет."

def cmd_chat_tracklist(peer: int) -> str:
    rows = db_all("SELECT kind, value FROM chat_tracks WHERE peer_id=? ORDER BY kind, value", (peer,))
    if not rows:
        return ("🔔 Трекеры беседы пусты.\n"
                "/track Ник — следить за игроком\n"
                "/trackonline N — порог онлайна\n"
                "/trackonlinefall N — падение онлайна до N\n"
                "/trackevent down|up|mod — событие сервера\n"
                f"Лимит — {CHAT_MAX_TRACKS} на беседу.")
    lines = [f"🔔 Трекеры беседы ({len(rows)}/{CHAT_MAX_TRACKS})\n"]
    for kind, value in rows:
        if kind == "player":
            row = db_one("SELECT online FROM players WHERE name_lower=?", (value,))
            mark = "🟢" if row and row[0] else "⚫"
            lines.append(f"{mark} игрок: {value}")
        elif kind == "online":
            lines.append(f"📈 онлайн ≥ {value}")
        elif kind == "online_fall":
            lines.append(f"📉 онлайн падает до {value}")
        else:
            lines.append(f"{EVENT_LABELS.get(kind, kind)}")
    lines.append("\nУбрать: /untrack Ник, /untrackonline N, /untrackonlinefall N, /untrackevent down|up|mod")
    return "\n".join(lines)

# ───────────────────────── КОМАНДЫ ───────────────────────────
def cmd_start(uid: int) -> str:
    text = (f"👋 Привет! Я слежу за сервером {SERVER_NAME}.\n\n"
            "🔎 Узнать про игрока: просто отправь мне его ник (например Laurent_Sykes) — покажу, "
            "в сети ли он, когда заходил и выходил, уровень и время в игре.\n\n"
            "📋 Команды:\n"
            "/server — статистика сервера: онлайн, пик, мод, версия, график\n"
            "/players — ники игроков, которые сейчас в игре\n"
            "/stats — статистика бота\n"
            "/profile — моя статистика за 7 игровых дней\n"
            "/setnick Ник — привязать свой игровой ник\n"
            "/pstats Ник — статистика любого игрока за 7 дней\n"
            "/hidekb — скрыть кнопки в личке\n\n"
            "🔔 Трекер (уведомления в личку):\n"
            "/track Ник — уведомить, когда игрок зайдёт или выйдет\n"
            "/untrack Ник — перестать следить\n"
            "/trackonline число — уведомить, когда онлайн сервера достигнет числа\n"
            "/untrackonline число — убрать порог\n"
            "/tracklist — всё, что отслеживаешь\n"
            f"🕔 Серверные сутки считаются с {DAY_START_HOUR:02d}:00 по МСК.\n"
            "/menu — показать кнопки")
    if is_staff(uid):
        text += ("\n\n👮 Команды администрации бота:\n"
                 "/admins — администрация сервера онлайн\n"
                 "/autoinfo — автоотчёт о сервере каждые 30 минут (вкл/выкл)")
    if is_owner(uid):
        text += ("\n\n👑 Команды основателя:\n"
                 "/allow ссылка — выдать доступ к боту\n"
                 "/deny ссылка — забрать доступ\n"
                 "/allowlist — список с доступом\n"
                 "/block ссылка — заблокировать пользователя\n"
                 "/unblock ссылка — разблокировать\n"
                 "/newadm ссылка — назначить админа бота\n"
                 "/deladm ссылка — снять админа бота\n"
                 "/admlist — список админов бота\n"
                 "/chats — рабочие беседы и их настройки\n"
                 "/setchatadmin <peer_id> ссылка — назначить админа беседы\n"
                 "/delchatadmin <peer_id> — снять админа беседы\n"
                 "/setrank Ник Ранг — задать ранг админа сервера\n"
                 "/delrank Ник — убрать ранг\n"
                 "📣 Рассылка: перешли мне пост из паблика или отправь сообщение с картинкой.")
    return text

def cmd_admins() -> str:
    if state["up"] is None:
        return "⏳ Данные ещё загружаются, попробуй через пару секунд."
    if not state["up"]:
        return "🔴 Сервер недоступен — список администрации получить нельзя."
    if state["players"] is None:
        return "⚠️ Сервер не отдаёт список игроков (возможно, онлайн больше 100)."
    online = sorted((p for p in state["players"] if p["name"].lower() in ADMINS_LOWER),
                    key=lambda p: p["name"].lower())
    lines = [f"👮 Администрация онлайн: {len(online)}/{len(ADMINS)}\n"]
    for p in online:
        rk = rank_of(p["name"])
        suffix = f" — {rk}" if rk else ""
        lines.append(f"🟢 {p['name']} [ID {p['id']}]{suffix}")
    if not online:
        lines.append("Сейчас никого нет в сети.")
    return "\n".join(lines)

def cmd_players(staff: bool) -> str:
    if state["up"] is None:
        return "⏳ Данные ещё загружаются, попробуй через пару секунд."
    if not state["up"]:
        return "🔴 Сервер недоступен."
    if state["players"] is None:
        online = (state["info"] or {}).get("online", "?")
        return f"⚠️ Сервер не отдаёт список игроков (возможно, онлайн больше 100). Онлайн: {online}"
    ps = [p for p in state["players"]
          if staff or p["name"].lower() not in SPECIAL_ADMINS]
    ps.sort(key=lambda p: p["id"])
    lines = [f"👥 Игроки онлайн: {len(ps)}\n"]
    for p in ps:
        mark = "👮" if staff and p["name"].lower() in ADMINS_LOWER else "•"
        lines.append(f"{mark} {p['name']} [{p['id']}]")
    return "\n".join(lines)

def cmd_server(uid: int = None, show_trackers: bool = True) -> str:
    if state["up"] is None:
        return "⏳ Данные ещё загружаются, попробуй через пару секунд."
    up = bool(state["up"])
    info = state["info"] or {}
    rules = info.get("rules", {})
    name = info.get("hostname") or SERVER_NAME
    lines = [f"{'🟢' if up else '🔴'} {name}",
             f"🌐 Адрес: {SERVER_HOST}:{SERVER_PORT}"]
    if up:
        o, mx = info.get("online", 0), info.get("max", 0) or 1
        filled = max(0, min(10, round(o / mx * 10)))
        lines.append(f"👥 Онлайн: {o}/{info.get('max', '?')} {'▰' * filled}{'▱' * (10 - filled)}")
    else:
        since = f" уже {fmt_dur(now() - state['since'])}" if state["since"] else ""
        lines.append(f"👥 Онлайн: — (сервер недоступен{since})")
    peak = db_one("SELECT MAX(online) FROM history WHERE ts >= ?", (now() - STATS_HOURS * 3600,))
    lines.append(f"📈 Пик за {STATS_HOURS}ч: {peak[0] if peak and peak[0] is not None else '—'}")
    lines.append(f"🔑 Доступ: {'закрытый (под паролем)' if info.get('passworded') else 'свободный'}")
    lines.append(f"📝 Игровой мод: {info.get('gamemode') or '—'}")
    lines.append(f"🌍 Язык: {info.get('language') or '—'}")
    lines.append(f"🔗 Сайт: {rules.get('weburl') or '—'}")
    lines.append(f"⚙️ Версия SA-MP: {rules.get('version') or '—'}")
    lines.append(f"🕒 Обновлено: {ago(state['last_ok']) if state['last_ok'] else '—'}")
    if up and state["players"] is not None:
        adm = sum(1 for p in state["players"] if p["name"].lower() in ADMINS_LOWER)
        lines.append(f"👮 Администраторов онлайн: {adm} из {len(ADMINS)}")

    ds = day_start_ts()
    mx_, avg, mn, adm_mx, cnt, first_ts = db_one(
        "SELECT MAX(online), AVG(online), MIN(online), MAX(admins), COUNT(*), MIN(ts) "
        "FROM history WHERE ts >= ?", (ds,))
    lines.append(f"\n📅 Серверные сутки с {DAY_START_HOUR:02d}:00 МСК (сброс через {fmt_dur(ds + 86400 - now())})")
    if cnt:
        peak_ts = db_one("SELECT ts FROM history WHERE ts >= ? ORDER BY online DESC, ts ASC LIMIT 1", (ds,))[0]
        lines += [f"Максимум онлайна: {mx_} (в {fmt_hm(peak_ts)})",
                  f"Средний онлайн: {round(avg)} | минимум: {mn}",
                  f"Максимум админов онлайн: {adm_mx}"]
        if first_ts - ds > 300:
            lines.append(f"ℹ️ Данные собираются с {fmt_hm(first_ts)} — бот был запущен позже начала суток.")
    else:
        lines.append("Данных за эти сутки пока нет.")
    prev = db_one("SELECT MAX(online) FROM history WHERE ts >= ? AND ts < ?", (ds - 86400, ds))
    if prev and prev[0] is not None:
        lines.append(f"Прошлые сутки: максимум {prev[0]}")
    if uid and show_trackers:
        lines.append(f"\n🔔 Трекеры: {tracker_count(uid)}/{MAX_TRACKS}")
    return "\n".join(lines)

def send_server(peer: int, uid: int, in_chat: bool):
    att = chart_attachment() if not in_chat else None
    send(peer, cmd_server(uid, show_trackers=not in_chat), None, att)

def cmd_stats() -> str:
    def q(sql, *a):
        return (db_one(sql, a) or [0])[0] or 0
    return (
        "📊 Статистика бота\n\n"
        f"Пользователей всего: {q('SELECT COUNT(*) FROM users')}\n"
        f"Активных за 24 ч: {q('SELECT COUNT(*) FROM users WHERE last_seen > ?', now() - 86400)}\n"
        f"Новых за 24 ч: {q('SELECT COUNT(*) FROM users WHERE first_seen > ?', now() - 86400)}\n"
        f"Доступ разрешён: {q('SELECT COUNT(*) FROM allowed_users')} (плюс админы и основатель)\n"
        f"Заблокировано: {q('SELECT COUNT(*) FROM blocked')}\n"
        f"Админов бота: {q('SELECT COUNT(*) FROM bot_admins')}\n"
        f"Всего запросов: {q('SELECT SUM(requests) FROM users')}\n"
        f"Игроков в базе мониторинга: {q('SELECT COUNT(*) FROM players')}\n"
        f"Трекеров (личных): {q('SELECT COUNT(*) FROM tracks') + q('SELECT COUNT(*) FROM online_tracks') + q('SELECT COUNT(*) FROM event_tracks')}\n"
        f"Трекеров бесед: {q('SELECT COUNT(*) FROM chat_tracks')}\n"
        f"Бесед: {q('SELECT COUNT(*) FROM chat_settings')}\n"
        f"Аптайм бота: {fmt_dur(now() - START_TS)}")

# ───────────────────────── ИГРОКИ ────────────────────────────
def play_seconds(low: str, start: int, end: int) -> int:
    t = now()
    rows = db_all("SELECT join_ts, COALESCE(leave_ts, ?) FROM sessions "
                  "WHERE name_lower=? AND join_ts < ? AND COALESCE(leave_ts, ?) > ?",
                  (t, low, end, t, start))
    return sum(max(0, min(l, end, t) - max(j, start)) for j, l in rows)

def pstats_text(name: str) -> str:
    low = name.lower()
    row = db_one("SELECT name, online, last_join, last_leave, score FROM players WHERE name_lower=?", (low,))
    if not row:
        return "🤷 Этого игрока бот ещё не видел на сервере."
    pname, online, last_join, last_leave, score = row
    ds = day_start_ts()
    lines = [f"📊 {pname} — статистика за {PROFILE_DAYS} игровых дней",
             f"(сутки считаются с {DAY_START_HOUR:02d}:00 МСК)\n"]
    total = 0
    for i in range(PROFILE_DAYS):
        start = ds - i * 86400
        secs = play_seconds(low, start, start + 86400)
        total += secs
        label = datetime.fromtimestamp(start, TZ).strftime("%d.%m")
        if i == 0:
            label += " (сегодня)"
        elif i == 1:
            label += " (вчера)"
        lines.append(f"{label}: {fmt_dur(secs) if secs >= 60 else '—'}")
    lines.append(f"\nВсего за {PROFILE_DAYS} дн.: {fmt_dur(total) if total >= 60 else '—'}")
    lines.append(f"Уровень: {score if score is not None else 'неизвестно'}")
    lines.append(f"Статус: {'🟢 в сети' if online else '⚫ не в сети'}")
    if last_join:
        lines.append(f"Последний заход: {fmt_dt(last_join)}")
    if last_leave and not online:
        lines.append(f"Последний выход: {fmt_dt(last_leave)}")
    since = int(kv_get("monitor_since") or now())
    if since > ds - (PROFILE_DAYS - 1) * 86400:
        lines.append(f"\nℹ️ Бот ведёт учёт с {fmt_dt(since)} (МСК) — раньше данных нет.")
    lines.append("Время считается по тому, когда бот видел игрока на сервере (точность ~15 сек).")
    return "\n".join(lines)

def player_card(row) -> str:
    name, online, last_join, last_leave = row[1], row[2], row[3], row[4]
    score = row[6] if len(row) > 6 else None
    lines = [f"{'🟢' if online else '⚫'} {name}", f"Статус: {'в сети' if online else 'не в сети'}"]
    if online:
        live = next((p for p in (state["players"] or []) if p["name"].lower() == name.lower()), None)
        if live:
            lines.append(f"ID: {live['id']} | Пинг: {live['ping']}")
        if last_join:
            lines.append(f"Подключился: {fmt_dt(last_join)} ({fmt_dur(now() - last_join)} назад)")
    else:
        if last_join:
            lines.append(f"Последнее подключение: {fmt_dt(last_join)}")
        if last_leave:
            lines.append(f"Последнее отключение: {fmt_dt(last_leave)} ({fmt_dur(now() - last_leave)} назад)")
    if score is not None:
        lines.append(f"Уровень: {score}")
    return "\n".join(lines) + "\n\nВремя — по МСК."

def card_kb(uid: int, name: str) -> str:
    kb = VkKeyboard(one_time=False, inline=True)
    if is_tracked(uid, name):
        kb.add_button("🔕 Не следить", color=VkKeyboardColor.NEGATIVE, payload={"cmd": "untrack", "name": name})
    else:
        kb.add_button("🔔 Следить", color=VkKeyboardColor.POSITIVE, payload={"cmd": "track", "name": name})
    kb.add_button("📊 За 7 дней", color=VkKeyboardColor.PRIMARY, payload={"cmd": "pstats", "name": name})
    return kb.get_keyboard()

def lookup(uid: int, text: str):
    q = text.strip().replace(" ", "_").lower()
    if len(q) < 2 or len(q) > 24:
        return "Введи ник игрока, например Laurent_Sykes.", None
    if q in SPECIAL_ADMINS and not is_staff(uid):
        return "🤷 Такого игрока бот ещё не видел на сервере.", None
    exact = db_one("SELECT * FROM players WHERE name_lower=?", (q,))
    if exact:
        return player_card(exact), card_kb(uid, exact[1])
    like = db_all("SELECT * FROM players WHERE name_lower LIKE ? "
                  "ORDER BY online DESC, last_seen DESC LIMIT 8", (f"%{q}%",))
    if not is_staff(uid):
        like = [r for r in like if r[1].lower() not in SPECIAL_ADMINS]
    if len(like) == 1:
        return player_card(like[0]), card_kb(uid, like[0][1])
    if like:
        return ("Нашёл несколько похожих ников, уточни:\n\n" + "\n".join(
            f"{'🟢' if r[2] else '⚫'} {r[1]}" for r in like)), None
    return ("🤷 Такого игрока бот ещё не видел на сервере. Возможно, он не заходил с момента "
            "запуска мониторинга или ник написан с ошибкой.\n"
            f"Чтобы получить уведомление, когда он появится: /track {text.strip()}"), None

# ───────────────────────── АВТООТЧЁТЫ ────────────────────────
def build_auto_report(uid: int) -> str:
    lines = [f"🔔 Автоотчёт — {fmt_dt(now())} (МСК)\n"]
    if state["up"] is None:
        return lines[0] + "Данные ещё загружаются."
    if not state["up"]:
        since = f" (уже {fmt_dur(now() - state['since'])})" if state["since"] else ""
        lines.append(f"🔴 Сервер недоступен{since}")
    else:
        i = state["info"]
        lines.append(f"🟢 Онлайн сервера: {i['online']}/{i['max']}")
        if state["players"] is None:
            lines.append("⚠️ Список игроков недоступен (онлайн больше 100?)")
        else:
            adm = sorted((p["name"] for p in state["players"] if p["name"].lower() in ADMINS_LOWER),
                         key=str.lower)
            lines.append(f"👮 Администраторов онлайн: {len(adm)} из {len(ADMINS)}")
            if adm:
                lines.append(", ".join(adm))
    ds = day_start_ts()
    mx = db_one("SELECT MAX(online) FROM history WHERE ts >= ?", (ds,))
    if mx and mx[0] is not None:
        lines.append(f"📈 Максимум за серверные сутки: {mx[0]}")
    tr = db_all("SELECT t.name, p.online, p.last_leave FROM tracks t "
                "LEFT JOIN players p ON p.name_lower = t.name_lower "
                "WHERE t.user_id=? ORDER BY t.name", (uid,))
    if tr:
        lines.append("\n👁 Игроки из твоего трекера:")
        for name, online, last_leave in tr:
            if online:
                lines.append(f"🟢 {name} — в сети")
            elif last_leave:
                lines.append(f"⚫ {name} — не в сети (вышел {ago(last_leave)})")
            else:
                lines.append(f"⚫ {name} — не в сети")
    lines.append("\nОтключить: /autoinfo")
    return "\n".join(lines)

def auto_loop():
    while True:
        try:
            for uid, last in db_all("SELECT user_id, last_sent FROM auto_notify"):
                if not is_staff(uid):
                    db_exec("DELETE FROM auto_notify WHERE user_id=?", (uid,))
                    continue
                if now() - last >= AUTO_INTERVAL:
                    db_exec("UPDATE auto_notify SET last_sent=? WHERE user_id=?", (now(), uid))
                    notify(uid, build_auto_report(uid))
        except Exception:
            log.exception("Ошибка автоотчётов")
        time.sleep(30)

def cmd_auto(uid: int) -> str:
    if db_one("SELECT 1 FROM auto_notify WHERE user_id=?", (uid,)):
        db_exec("DELETE FROM auto_notify WHERE user_id=?", (uid,))
        return "🔕 Автоотчёты выключены."
    db_exec("INSERT INTO auto_notify VALUES(?,?)", (uid, now()))
    send(uid, "🔔 Автоотчёты включены: каждые 30 минут буду присылать данные о сервере. "
              "Выключить — /autoinfo. Вот первый отчёт:")
    return build_auto_report(uid)

# ───────────────────────── РАССЫЛКА ──────────────────────────
pending_bc = {}
BC_TYPES = {"photo", "video", "audio", "doc", "wall", "poll", "market", "audio_message", "graffiti"}

def collect_attachments(msg: dict) -> str:
    out = []
    for a in msg.get("attachments") or []:
        t = a.get("type")
        if t not in BC_TYPES:
            continue
        o = a.get(t) or {}
        owner = o.get("owner_id", o.get("from_id"))
        oid = o.get("id")
        if owner is None or oid is None:
            continue
        s = f"{t}{owner}_{oid}"
        if o.get("access_key"):
            s += f"_{o['access_key']}"
        out.append(s)
    return ",".join(out[:10])

def recipients_count() -> int:
    return (db_one("SELECT COUNT(*) FROM users WHERE user_id NOT IN (SELECT user_id FROM blocked)") or [0])[0]

def start_broadcast_preview(owner: int, text: str, att: str):
    bid = secrets.token_hex(3)
    pending_bc[owner] = {"id": bid, "text": text, "att": att, "ts": now()}
    kb = VkKeyboard(one_time=False, inline=True)
    kb.add_button("✅ Разослать", color=VkKeyboardColor.POSITIVE, payload={"cmd": "bc_ok", "id": bid})
    kb.add_button("❌ Отмена", color=VkKeyboardColor.NEGATIVE, payload={"cmd": "bc_no", "id": bid})
    head = f"📣 Предпросмотр рассылки. Получателей: {recipients_count()} (включая тебя).\n"
    send(owner, head + ("\n" + text if text else ""), kb.get_keyboard(), att or None)

def run_broadcast(owner: int, text: str, att: str):
    ids = [r[0] for r in db_all("SELECT user_id FROM users WHERE user_id NOT IN (SELECT user_id FROM blocked)")]
    ok = fail = 0
    for i in range(0, len(ids), 100):
        batch = ids[i:i + 100]
        params = dict(user_ids=",".join(map(str, batch)), message=(text or "")[:4000],
                      random_id=get_random_id())
        if att:
            params["attachment"] = att
        try:
            with _vk_lock:
                res = vk.messages.send(**params)
            if isinstance(res, list):
                for r in res:
                    if isinstance(r, dict) and r.get("error"):
                        fail += 1
                    else:
                        ok += 1
            else:
                ok += len(batch)
        except Exception as e:
            log.error("Рассылка: пакет не отправлен: %s", e)
            fail += len(batch)
        time.sleep(0.3)
    send(owner, f"📣 Рассылка завершена.\nДоставлено: {ok}\nНе доставлено: {fail} "
                "(эти люди не разрешили сообщения от сообщества или заблокировали его).")

def chat_kb(peer: int) -> str:
    cfg = chat_cfg(peer)
    kb = VkKeyboard(one_time=False, inline=True)

    def b(label, key, val, color):
        mark = "✅ " if cfg[key] else "❌ "
        kb.add_button(mark + label, color=color,
                      payload={"cmd": "chat_toggle", "peer": peer, "key": key, "val": val})

    b("Трекеры", "tracks", 0 if cfg["tracks"] else 1, VkKeyboardColor.PRIMARY)
    kb.add_line()
    b("Падение", "down", 0 if cfg["down"] else 1, VkKeyboardColor.NEGATIVE)
    b("Восстановление", "up", 0 if cfg["up"] else 1, VkKeyboardColor.POSITIVE)
    return kb.get_keyboard()

def cmd_chats(uid: int) -> str:
    rows = db_all("SELECT peer_id, tracks, down, up, title FROM chat_settings")
    if not rows:
        return ("⚙️ Известных бесед пока нет.\n"
                "Добавь бота в беседу и напиши там /chatid — бот запомнит её.")
    lines = ["⚙️ Известные беседы:\n"]
    def onoff(v): return "вкл" if v else "выкл"
    for peer, tr, dn, up, title in rows:
        adm = chat_admin_of(peer)
        adm_s = f"vk.com/id{adm}" if adm else "не назначен"
        cnt = chat_track_count(peer)
        name_s = f" «{title}»" if title else ""
        lines.append(
            f"ID: {peer}{name_s}\n"
            f"  админ: {adm_s}\n"
            f"  трекеры: {onoff(tr)} | падение: {onoff(dn)} | восстановление: {onoff(up)}\n"
            f"  трекеров: {cnt}/{CHAT_MAX_TRACKS}")
    lines.append("\nНастройка: /setchatadmin <peer_id> ссылка, /delchatadmin <peer_id>")
    return "\n".join(lines)

# ───────────────────────── ОБРАБОТКА СООБЩЕНИЙ ───────────────
def resolve_user(arg: str):
    arg = arg.strip()
    m = re.match(r"^\[id(\d+)\|", arg)
    if m:
        return int(m.group(1))
    m = re.search(r"vk\.com/([A-Za-z0-9_.]+)", arg)
    name = m.group(1) if m else arg.lstrip("@*")
    if not name:
        return None
    if re.fullmatch(r"(?:id)?\d+", name):
        return int(re.sub(r"^id", "", name))
    try:
        with _vk_lock:
            res = vk.users.get(user_ids=name)
        return res[0]["id"] if res else None
    except Exception:
        return None

TEXT_ALIASES = {
    "start": {"/start", "/help", "начать", "помощь", "start"},
    "menu": {"/menu", "меню", "кнопки"},
    "hidekb": {"/hidekb", "скрыть", "убрать кнопки"},
    "admins": {"/admins", "админы", "администрация"},
    "server": {"/server", "сервер"},
    "players": {"/players", "игроки"},
    "stats": {"/stats", "статистика"},
    "profile": {"/profile", "профиль"},
    "tracklist": {"/tracklist", "трекер"},
    "auto": {"/autoinfo", "автоотчёт", "автоотчет"},
}
STAFF_ACTIONS = {"admins", "auto"}
OWNER_ACTIONS = {"block", "unblock", "newadm", "deladm", "admlist", "broadcast", "bc_ok", "bc_no",
                 "setchatadmin", "delchatadmin", "chats", "setrank", "delrank",
                 "allow", "deny", "allowlist"}

DM_ONLY = {"track", "untrack", "trackonline", "untrackonline", "trackonlinefall", "untrackonlinefall", 
           "tracklist", "toggle", "profile", "setnick", "auto", "broadcast", "bc_ok", "bc_no", 
           "newadm", "deladm", "admlist", "setchatadmin", "delchatadmin", "chats", "setrank", 
           "delrank", "chat_toggle", "allow", "deny", "allowlist"}

CHAT_COMMANDS = (
    "📋 Команды бота в беседе:\n\n"
    "/server — статистика сервера\n"
    "/players — игроки онлайн (только staff)\n"
    "/admins — администрация онлайн\n"
    "/chatid — peer_id этой беседы\n"
    "/cmd — этот список\n\n"
    "🔔 Трекеры беседы (до 10 слотов):\n"
    "/track Ник — следить за игроком\n"
    "/untrack Ник\n"
    "/trackonline N — уведомить, когда онлайн СТАНЕТ N\n"
    "/trackonlinefall N — уведомить, когда онлайн УПАДЁТ до N\n"
    "/untrackonline N\n"
    "/untrackonlinefall N\n"
    "/trackevent down — подписаться на падение сервера\n"
    "/trackevent up — подписаться на восстановление\n"
    "/untrackevent down|up|mod\n"
    "/tracklist — текущие трекеры беседы\n"
    "Добавлять/убирать трекеры может только админ беседы или основатель.\n\n"
    "👑 Основатель:\n"
    "/newadm ссылка, /deladm ссылка\n\n"
    "💬 Остальные настройки уведы (трекеры, падение, восстановление) — "
    "админ беседы в личке бота: /chats"
)

def handle(msg: dict):
    uid = msg.get("from_id", 0)
    peer = msg["peer_id"]
    if uid <= 0:
        return
    raw = re.sub(r"^\[club\d+\|[^\]]*\]\s*", "", (msg.get("text") or "")).strip()
    in_chat = peer >= 2_000_000_000

    pdata = {}
    if msg.get("payload"):
        try:
            pl = json.loads(msg["payload"])
            if isinstance(pl, dict):
                pdata = pl
        except (ValueError, TypeError):
            pass
    pcmd = pdata.get("cmd") or pdata.get("command")
    atts = collect_attachments(msg)
    
    if not raw and not pcmd and not atts:
        return

    # 5.9.1: Игнорируем ВСЕХ, у кого нет доступа (включая /start)
    if not has_access(uid):
        return

    if in_chat and not (raw.startswith("/") or pcmd):
        return

    owner = is_owner(uid)
    staff = is_staff(uid)
    if not owner and db_one("SELECT 1 FROM blocked WHERE user_id=?", (uid,)):
        return
    
    t = now()
    db_exec("INSERT INTO users(user_id,first_seen,last_seen,requests) VALUES(?,?,?,1) "
            "ON CONFLICT(user_id) DO UPDATE SET last_seen=?, requests=requests+1", (uid, t, t, t))

    parts = raw.split(maxsplit=1)
    cmd = parts[0].lower() if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else ""
    low = raw.lower()

    action = pcmd
    if not action:
        for name, variants in TEXT_ALIASES.items():
            if low in variants:
                action = name
                break
    if not action and cmd.startswith("/"):
        action = cmd[1:].split("@")[0]
    if not arg:
        arg = str(pdata.get("name") or "")

    log.info("Сообщение от %s (peer=%s): %r payload=%r", uid, peer, raw, msg.get("payload"))

    if action == "start":
        return send(peer, cmd_start(uid))

    if in_chat:
        chat_ensure(peer)

    if pcmd == "chat_toggle" and not in_chat and is_chat_admin(uid, int(pdata.get("peer", 0))):
        p = int(pdata.get("peer", 0))
        if p in all_chat_peers():
            key = pdata.get("key")
            val = int(pdata.get("val", 0))
            if key in ("tracks", "down", "up"):
                chat_cfg_set(p, key, val)
                cfg = chat_cfg(p)
                state_s = {k: ("вкл" if cfg[k] else "выкл") for k in ("tracks", "down", "up")}
                return send(peer,
                            f"⚙️ Беседа {p}\n"
                            f"трекеры: {state_s['tracks']}\n"
                            f"падение: {state_s['down']}\n"
                            f"восстановление: {state_s['up']}",
                            chat_kb(p))
        return

    if owner and not in_chat and atts and not pcmd and not raw.startswith("/"):
        return start_broadcast_preview(uid, raw, atts)

    def unknown():
        send(peer, "Неизвестная команда. Напиши /cmd (в беседе) или /start (в личке).")

    if action == "myid":
        return send(peer, f"Твой VK ID: {uid}")
    if action in STAFF_ACTIONS and not staff:
        return unknown()
    if action in OWNER_ACTIONS and not owner:
        return unknown()
    
    if in_chat and action in DM_ONLY:
        return send(peer, "Эта команда работает в личных сообщениях с сообществом — напиши мне в ЛС.")

    if action == "hidekb":
        return send(peer, "Кнопки скрыты. Вернуть: /menu", keyboard="")

    if action == "cmd":
        return send(peer, CHAT_COMMANDS)
    if action == "chatid":
        return send(peer, f"peer_id этой беседы: {peer}\n"
                          f"Отправь основателю в личку: /setchatadmin {peer} vk.com/username")

    if action == "menu":
        return send(peer, "Кнопки включены 👇", kb_for(uid))
    if action == "server":
        return send_server(peer, uid, in_chat)
    if action == "players":
        return send_long(peer, cmd_players(staff))
    if action == "stats":
        return send(peer, cmd_stats())
    if action == "admins":
        return send(peer, cmd_admins())
    if action == "auto":
        return send(peer, cmd_auto(uid))

    if action in ("track", "untrack", "trackonline", "untrackonline", "trackonlinefall", "untrackonlinefall", "trackevent", "untrackevent"):
        if not in_chat:
            if action == "track":
                text = cmd_track(uid, arg)
                return send(peer, text, card_kb(uid, arg.replace(" ", "_"))
                            if NICK_RE.match(arg.replace(" ", "_")) else None)
            if action == "untrack":
                text = cmd_untrack(uid, arg)
                return send(peer, text, card_kb(uid, arg.replace(" ", "_"))
                            if NICK_RE.match(arg.replace(" ", "_")) else None)
            if action == "trackonline":
                return send(peer, cmd_trackonline(uid, arg))
            if action == "untrackonline":
                return send(peer, cmd_untrackonline(uid, arg))
            return unknown()
        
        if not is_chat_admin(uid, peer):
            return send(peer, "Трекерами беседы управляет только её админ или основатель.")
        if action == "track":
            if not arg:
                return send(peer, "Использование: /track Ник")
            nick = arg.replace(" ", "_")
            if not NICK_RE.match(nick):
                return send(peer, "Некорректный ник.")
            return send(peer, chat_add_track(peer, "player", nick.lower(), uid))
        if action == "untrack":
            if not arg:
                return send(peer, "Использование: /untrack Ник")
            return send(peer, chat_del_track(peer, "player", arg.replace(" ", "_").lower()))
        if action == "trackonline":
            if not arg.isdigit() or not (1 <= int(arg) <= 1000):
                return send(peer, "Использование: /trackonline N (1–1000)")
            return send(peer, chat_add_track(peer, "online", str(int(arg)), uid))
        if action == "untrackonline":
            if not arg.isdigit():
                return send(peer, "Использование: /untrackonline N")
            return send(peer, chat_del_track(peer, "online", str(int(arg))))
        if action == "trackonlinefall":
            if not arg.isdigit() or not (1 <= int(arg) <= 1000):
                return send(peer, "Использование: /trackonlinefall N (1–1000)")
            return send(peer, chat_add_track(peer, "online_fall", str(int(arg)), uid))
        if action == "untrackonlinefall":
            if not arg.isdigit():
                return send(peer, "Использование: /untrackonlinefall N")
            return send(peer, chat_del_track(peer, "online_fall", str(int(arg))))
        if action == "trackevent":
            k = arg.lower()
            if k not in CHAT_EVENTS:
                return send(peer, "Использование: /trackevent down|up|mod")
            return send(peer, chat_add_track(peer, k, "", uid))
        if action == "untrackevent":
            k = arg.lower()
            if k not in CHAT_EVENTS:
                return send(peer, "Использование: /untrackevent down|up|mod")
            return send(peer, chat_del_track(peer, k, ""))

    if action == "tracklist":
        if in_chat:
            return send(peer, cmd_chat_tracklist(peer))
        return send(peer, cmd_tracklist(uid))

    if action == "chats":
        return send(peer, cmd_chats(uid))
    if action == "setchatadmin":
        if not arg:
            return send(peer, "Использование: /setchatadmin <peer_id> ссылка")
        p2 = arg.split(maxsplit=1)
        if len(p2) != 2 or not p2[0].isdigit():
            return send(peer, "Использование: /setchatadmin <peer_id> ссылка")
        peer_id = int(p2[0])
        if peer_id not in all_chat_peers():
            return send(peer, f"Беседа {peer_id} боту неизвестна. Добавь бота в беседу и напиши там /chatid.")
        target = resolve_user(p2[1])
        if not target:
            return send(peer, "Не нашёл такого пользователя.")
        db_exec("INSERT OR REPLACE INTO chat_admins VALUES(?,?,?)", (peer_id, target, now()))
        notify(target, f"👮 Тебя назначили админом беседы {peer_id}.\n"
                       f"Управление уведомлениями — в личке бота, команда /chats.")
        return send(peer, f"✅ vk.com/id{target} назначен админом беседы {peer_id}.")
    if action == "delchatadmin":
        if not arg.isdigit():
            return send(peer, "Использование: /delchatadmin <peer_id>")
        peer_id = int(arg)
        n = db_exec("DELETE FROM chat_admins WHERE peer_id=?", (peer_id,))
        return send(peer, f"✅ Админ беседы {peer_id} снят." if n else "У беседы не было админа.")
    if action == "setrank":
        if not arg:
            return send(peer, "Использование: /setrank Ник Ранг")
        p2 = arg.split(maxsplit=1)
        if len(p2) != 2:
            return send(peer, "Использование: /setrank Ник Ранг")
        nick, rk = p2[0].replace(" ", "_"), p2[1].strip()
        if nick.lower() not in ADMINS_LOWER:
            return send(peer, f"{nick} нет в списке админов сервера.")
        db_exec("INSERT OR REPLACE INTO admin_ranks VALUES(?,?)", (nick.lower(), rk))
        return send(peer, f"✅ Ранг для {nick}: {rk}")
    if action == "delrank":
        if not arg:
            return send(peer, "Использование: /delrank Ник")
        nick = arg.replace(" ", "_").lower()
        n = db_exec("DELETE FROM admin_ranks WHERE name_lower=?", (nick,))
        return send(peer, "✅ Ранг удалён." if n else "У этого ника не было ранга.")

    if action == "allow":
        if not arg:
            return send(peer, "Использование: /allow ссылка")
        target = resolve_user(arg)
        if not target:
            return send(peer, "Не нашёл такого пользователя.")
        db_exec("INSERT OR IGNORE INTO allowed_users VALUES(?,?,?)", (target, uid, now()))
        notify(target, "✅ Тебе выдали доступ к боту! Напиши /start, чтобы увидеть команды.")
        return send(peer, f"✅ vk.com/id{target} получил доступ к боту.")
    if action == "deny":
        if not arg:
            return send(peer, "Использование: /deny ссылка")
        target = resolve_user(arg)
        if not target:
            return send(peer, "Не нашёл такого пользователя.")
        db_exec("DELETE FROM allowed_users WHERE user_id=?", (target,))
        notify(target, "⛔ Твой доступ к боту был закрыт основателем.")
        return send(peer, f"✅ Доступ vk.com/id{target} закрыт.")
    if action == "allowlist":
        rows = db_all("SELECT user_id FROM allowed_users")
        if not rows:
            return send(peer, "В белом списке никого нет.")
        lines = ["👥 Пользователи с доступом:\n"]
        for (u,) in rows:
            try:
                info = vk.users.get(user_ids=u)[0]
                lines.append(f"• {info['first_name']} {info['last_name']} (id{u})")
            except Exception:
                lines.append(f"• id{u}")
        return send(peer, "\n".join(lines))

    if action == "setnick":
        nick = arg.replace(" ", "_")
        if not NICK_RE.match(nick):
            return send(peer, "Использование: /setnick Ник_Фамилия")
        db_exec("UPDATE users SET nick=? WHERE user_id=?", (nick, uid))
        return send(peer, f"✅ Ник {nick} привязан. Кнопка «Профиль» покажет твою статистику.")
    if action == "profile":
        row = db_one("SELECT nick FROM users WHERE user_id=?", (uid,))
        if not row or not row[0]:
            return send(peer, "Сначала привяжи свой ник: /setnick Ник_Фамилия")
        return send(peer, pstats_text(row[0]))
    if action == "pstats":
        if not arg:
            return send(peer, "Использование: /pstats Ник_Фамилия")
        return send(peer, pstats_text(arg.replace(" ", "_")))

    if action == "toggle":
        msg_text = toggle_tracker(uid, pdata)
        return send(peer, msg_text, server_kb(uid))

    if action in ("block", "unblock", "newadm", "deladm"):
        if in_chat:
            if action not in ("newadm", "deladm"):
                return send(peer, "Эта команда работает в личке с сообществом.")
        if not arg:
            return send(peer, f"Использование: /{action} ссылка_на_профиль_или_ID")
        target = resolve_user(arg)
        if not target:
            return send(peer, "Не нашёл такого пользователя.")
        if target == ADMIN_VK_ID and action in ("block", "deladm", "newadm"):
            return send(peer, "Основателя это не касается 🙂")
        if action == "block":
            db_exec("INSERT OR REPLACE INTO blocked VALUES(?,?)", (target, now()))
            db_exec("DELETE FROM bot_admins WHERE user_id=?", (target,))
            return send(peer, f"⛔ Пользователь id{target} заблокирован.")
        if action == "unblock":
            n = db_exec("DELETE FROM blocked WHERE user_id=?", (target,))
            return send(peer, f"✅ id{target} разблокирован." if n else "Этого пользователя нет в блоке.")
        if action == "newadm":
            if db_one("SELECT 1 FROM bot_admins WHERE user_id=?", (target,)):
                return send(peer, f"id{target} уже админ бота.")
            db_exec("DELETE FROM blocked WHERE user_id=?", (target,))
            db_exec("INSERT INTO bot_admins VALUES(?,?,?)", (target, uid, now()))
            notify(target, "👮 Тебя назначили админом бота.")
            return send(peer, f"✅ id{target} назначен админом бота.")
        n = db_exec("DELETE FROM bot_admins WHERE user_id=?", (target,))
        db_exec("DELETE FROM auto_notify WHERE user_id=?", (target,))
        if n:
            send(target, "Ты больше не админ бота.", KB_USER)
        return send(peer, f"✅ id{target} больше не админ бота." if n else "Он не был админом бота.")
    if action == "admlist":
        rows = db_all("SELECT user_id FROM bot_admins")
        if not rows:
            return send(peer, "Админов бота пока нет. Назначить: /newadm ссылка")
        return send(peer, "👮 Админы бота:\n" + "\n".join(f"vk.com/id{r[0]}" for r in rows))
    if action == "broadcast":
        if not arg:
            return send(peer, "Использование: /broadcast текст. Или перешли мне пост / картинку.")
        return start_broadcast_preview(uid, arg, "")
    if action in ("bc_ok", "bc_no"):
        pb = pending_bc.get(uid)
        if not pb or pb["id"] != pdata.get("id") or now() - pb["ts"] > 600:
            return send(peer, "Эта рассылка уже неактуальна. Пришли пост заново.")
        pending_bc.pop(uid, None)
        if action == "bc_no":
            return send(peer, "❌ Рассылка отменена.")
        send(peer, "📤 Рассылаю…")
        threading.Thread(target=run_broadcast, args=(uid, pb["text"], pb["att"]), daemon=True).start()
        return

    if raw.startswith("/") or not raw:
        return
    if in_chat:
        return
    text, kb = lookup(uid, raw)
    send(peer, text, kb)

def main():
    if GROUP_ID == 0 or not VK_TOKEN:
        raise SystemExit("Заполни VK_TOKEN и GROUP_ID в настройках файла или переменных окружения.")
    if ADMIN_VK_ID == 0:
        log.warning("ADMIN_VK_ID не задан — команды основателя недоступны.")
    if not HAVE_MPL:
        log.warning("matplotlib не установлен — график онлайна показываться не будет.")
    threading.Thread(target=monitor_loop, daemon=True).start()
    threading.Thread(target=auto_loop, daemon=True).start()
    log.info("Бот запущен (v5.9.1), слушаю сообщества %s.", GROUP_ID)
    while True:
        try:
            longpoll = VkBotLongPoll(vk_session, GROUP_ID)
            for event in longpoll.listen():
                if event.type != VkBotEventType.MESSAGE_NEW:
                    continue
                try:
                    msg = event.obj.get("message") or event.obj
                    handle(msg)
                except Exception:
                    log.exception("Ошибка обработки сообщения")
        except Exception as e:
            log.error("Long Poll оборвался: %s. Переподключение через 5 сек.", e)
            time.sleep(5)

if __name__ == "__main__":
    main()