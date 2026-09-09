import time
import os
import sys
import hashlib
import base64
import logging
import asyncio
import multiprocessing
from multiprocessing import Process, Queue, Event

from dotenv import load_dotenv
from nacl.signing import SigningKey
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
    CallbackQueryHandler,
)

load_dotenv()
BOT_TOKEN = os.getenv("8813733175:AAEX6WkDHnDCRz8RwcNpORAhZQxDqjGmi3g")
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
# Show errors from telegram handlers
logging.getLogger("telegram.ext.Application").setLevel(logging.ERROR)

# ── BIP39 wordlist ────────────────────────────────────────────────────────────

_WORDLIST: list[str] = []

def _load_wordlist() -> bool:
    """Download BIP39 English wordlist once at startup. Returns True on success."""
    global _WORDLIST
    if _WORDLIST:
        return True
    import urllib.request
    url = "https://raw.githubusercontent.com/trezor/python-mnemonic/master/src/mnemonic/wordlist/english.txt"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            _WORDLIST = r.read().decode().strip().split("\n")
        return len(_WORDLIST) >= 2048
    except Exception as e:
        logging.warning(f"Не удалось загрузить BIP39 wordlist: {e}")
        return False

def privkey_to_mnemonic(privkey_bytes: bytes, word_count: int = 24) -> str | None:
    """
    Derive a BIP39-style mnemonic from a 32-byte private key.
    word_count: 12 (128-bit security) or 24 (256-bit security).
    """
    if not _WORDLIST or len(_WORDLIST) < 2048:
        return None

    # For 12 words we need 128 bits of entropy, for 24 words — 256 bits
    entropy_len = 16 if word_count == 12 else 32  # bytes
    # Derive deterministic entropy from the key
    entropy = hashlib.sha256(privkey_bytes).digest()[:entropy_len]

    # BIP39: append checksum bits (entropy_len*8 // 32 bits)
    checksum_bits = (entropy_len * 8) // 32
    hash_byte = hashlib.sha256(entropy).digest()[0]
    # Build bit string: entropy bits + checksum bits
    entropy_int = int.from_bytes(entropy, "big")
    total_bits = entropy_len * 8 + checksum_bits
    combined = (entropy_int << checksum_bits) | (hash_byte >> (8 - checksum_bits))

    # Extract 11-bit groups (right to left, then reverse)
    words = []
    mask = 0x7FF  # 11 bits
    for _ in range(word_count):
        words.append(_WORDLIST[combined & mask])
        combined >>= 11
    return " ".join(reversed(words))

# ── TON address generation ────────────────────────────────────────────────────

def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
    return crc & 0xFFFF

def pubkey_to_address(pub: bytes, bounceable: bool = False) -> str:
    """v4r2 workchain=0. bounceable=False -> UQ..., True -> EQ..."""
    state = bytes([0x00]) + pub
    addr_hash = hashlib.sha256(state).digest()
    tag = 0x11 if bounceable else 0x51
    raw = bytes([tag, 0x00]) + addr_hash
    crc = _crc16(raw)
    return base64.urlsafe_b64encode(raw + bytes([crc >> 8, crc & 0xFF])).decode()

# ── Worker process ────────────────────────────────────────────────────────────

def _worker(proc_id: int, pattern: str, result_q: Queue, stop: Event,
            case_sensitive: bool, bounceable: bool):
    # pattern already normalised by parent
    count = 0
    while not stop.is_set():
        sk = SigningKey(os.urandom(32))
        pub = bytes(sk.verify_key)
        addr = pubkey_to_address(pub, bounceable=bounceable)
        count += 1

        addr_cmp = addr if case_sensitive else addr.upper()
        if addr_cmp.endswith(pattern):
            seed_bytes = bytes(sk._signing_key)[:32]
            result_q.put({"type": "found", "address": addr, "privkey": seed_bytes.hex()})
            stop.set()
            return

        if count % 10_000 == 0:
            result_q.put({"type": "progress", "proc_id": proc_id, "attempts": count})

# ── User settings ─────────────────────────────────────────────────────────────

user_settings: dict = {}

def get_settings(chat_id: int) -> dict:
    if chat_id not in user_settings:
        user_settings[chat_id] = {
            "seed_words": 24,
            "case_sensitive": False,
            "bounceable": False,
        }
    return user_settings[chat_id]

# ── Active searches ───────────────────────────────────────────────────────────

sessions: dict = {}

async def _watch(chat_id: int, context: ContextTypes.DEFAULT_TYPE):
    sess = sessions.get(chat_id)
    if not sess:
        return

    q: Queue = sess["q"]
    stop: Event = sess["stop"]
    last: dict = {}
    msg_id = None

    while not stop.is_set() or not q.empty():
        await asyncio.sleep(2)
        items = []
        while not q.empty():
            try:
                items.append(q.get_nowait())
            except Exception:
                break

        found = None
        for item in items:
            if item["type"] == "found":
                found = item
            elif item["type"] == "progress":
                last[item["proc_id"]] = item["attempts"]

        total = sum(last.values())

        if found:
            stop.set()
            for p in sess["procs"]:
                p.terminate()
                p.join(timeout=2)

            seed_words = sess["seed_words"]
            privkey_hex = found["privkey"]
            mnemonic = privkey_to_mnemonic(bytes.fromhex(privkey_hex), word_count=seed_words)
            if mnemonic:
                seed_text = f"Сид-фраза ({seed_words} слов):\n{mnemonic}"
            else:
                seed_text = f"Приватный ключ (hex):\n{privkey_hex}"

            # Send address first
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"Найдено!\n\nАдрес: {found['address']}",
            )
            # Send seed immediately after — no button needed
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"🔑 {seed_text}\n\nСохрани в надёжном месте.",
            )
            if msg_id:
                try:
                    await context.bot.delete_message(chat_id=chat_id, message_id=msg_id)
                except Exception:
                    pass
            sessions.pop(chat_id, None)
            return

        if total > 0:
            text = f"Ищу ...{sess['pattern']}\nПроверено: {total:,} адресов"
            if msg_id:
                try:
                    await context.bot.edit_message_text(
                        chat_id=chat_id, message_id=msg_id, text=text
                    )
                except Exception:
                    pass
            else:
                m = await context.bot.send_message(chat_id=chat_id, text=text)
                msg_id = m.message_id

    sessions.pop(chat_id, None)

# ── Settings UI ───────────────────────────────────────────────────────────────

# ── Settings UI ───────────────────────────────────────────────────────────────

def _settings_txt(chat_id: int) -> str:
    s = get_settings(chat_id)
    words = s["seed_words"]
    case = "вкл" if s["case_sensitive"] else "выкл"
    fmt = "EQ (bounceable)" if s["bounceable"] else "UQ (non-bounceable)"
    return (
        "⚙️ Текущие настройки:\n"
        f"  Сид-фраза: {words} слов\n"
        f"  Регистр: {case}\n"
        f"  Формат адреса: {fmt}\n\n"
        "Команды для изменения:\n"
        "/seed12 — сид-фраза 12 слов\n"
        "/seed24 — сид-фраза 24 слова (TON стандарт)\n"
        "/caseon — учитывать регистр (MOON ≠ moon)\n"
        "/caseoff — игнорировать регистр (MOON = moon)\n"
        "/addruq — формат UQ... (non-bounceable)\n"
        "/addreq — формат EQ... (bounceable)"
    )

async def cmd_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(_settings_txt(update.effective_chat.id))

async def cmd_seed12(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_settings(update.effective_chat.id)
    s["seed_words"] = 12
    await update.message.reply_text("✅ Сид-фраза: 12 слов")

async def cmd_seed24(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_settings(update.effective_chat.id)
    s["seed_words"] = 24
    await update.message.reply_text("✅ Сид-фраза: 24 слова")

async def cmd_caseon(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_settings(update.effective_chat.id)
    s["case_sensitive"] = True
    await update.message.reply_text("✅ Регистр: вкл (MOON ≠ moon)")

async def cmd_caseoff(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_settings(update.effective_chat.id)
    s["case_sensitive"] = False
    await update.message.reply_text("✅ Регистр: выкл (MOON = moon)")

async def cmd_addruq(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_settings(update.effective_chat.id)
    s["bounceable"] = False
    await update.message.reply_text("✅ Формат: UQ... (non-bounceable)")

async def cmd_addreq(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_settings(update.effective_chat.id)
    s["bounceable"] = True
    await update.message.reply_text("✅ Формат: EQ... (bounceable)")



# ── Search statistics ─────────────────────────────────────────────────────────

def get_stats(chat_id: int):
    if not hasattr(get_stats, "_data"):
        get_stats._data = {}
    return get_stats._data.setdefault(chat_id, {
        "total": 0,
        "last_total": 0,
        "last_time": time.time(),
        "rate": 0.0,
        "started": 0,
    })

def update_stats(chat_id: int, amount: int):
    st = get_stats(chat_id)
    st["total"] += amount
    now = time.time()
    elapsed = now - st["last_time"]
    if elapsed >= 1:
        st["rate"] = (st["total"] - st["last_total"]) / elapsed
        st["last_total"] = st["total"]
        st["last_time"] = now

def stats_text(chat_id: int):
    st = get_stats(chat_id)
    return (
        "📊 <b>Статистика поиска</b>\n\n"
        f"🔢 Всего запросов: <b>{st['total']:,}</b>\n"
        f"⚡ Скорость: <b>{st['rate']:.2f}/сек</b>\n"
        f"🚀 За последнюю секунду: <b>{st['total'] - st['last_total']:,}</b>\n"
    )

# ── Inline menu ───────────────────────────────────────────────────────────────

def main_menu_keyboard(chat_id: int):
    s = get_settings(chat_id)
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔎 Новый поиск", callback_data="new_search"),
            InlineKeyboardButton("⚙️ Настройки", callback_data="settings"),
        ],
        [InlineKeyboardButton("🛑 Остановить поиск", callback_data="stop")],
        [InlineKeyboardButton("📊 Статистика", callback_data="stats")],
        [
            InlineKeyboardButton(f"🔑 Сид: {s['seed_words']} слов", callback_data="seed_menu"),
            InlineKeyboardButton(
                f"🔤 Регистр: {'ВКЛ' if s['case_sensitive'] else 'ВЫКЛ'}",
                callback_data="case_menu"
            ),
        ],
        [InlineKeyboardButton(
            f"💎 Адрес: {'EQ' if s['bounceable'] else 'UQ'}",
            callback_data="address_menu"
        )],
    ])

def settings_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔑 12 слов", callback_data="seed12"),
            InlineKeyboardButton("🔑 24 слова", callback_data="seed24"),
        ],
        [
            InlineKeyboardButton("🔤 Регистр ВКЛ", callback_data="caseon"),
            InlineKeyboardButton("🔤 Регистр ВЫКЛ", callback_data="caseoff"),
        ],
        [
            InlineKeyboardButton("💎 UQ", callback_data="addruq"),
            InlineKeyboardButton("💎 EQ", callback_data="addreq"),
        ],
        [InlineKeyboardButton("◀️ Назад", callback_data="menu")],
    ])

async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "💎 <b>TON Address Finder</b>\n\n"
        "Отправь паттерн до 8 символов, чтобы начать поиск.\n"
        "Например: <code>MOON</code>\n\n"
        "Выбери действие ниже:",
        parse_mode="HTML",
        reply_markup=main_menu_keyboard(update.effective_chat.id),
    )

async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id
    data = query.data
    s = get_settings(chat_id)

    if data == "menu":
        await query.edit_message_text(
            "💎 <b>TON Address Finder</b>\n\n"
            "Отправь паттерн до 8 символов, чтобы начать поиск.\n"
            "Например: <code>MOON</code>\n\n"
            "Выбери действие ниже:",
            parse_mode="HTML",
            reply_markup=main_menu_keyboard(chat_id),
        )

    elif data == "stats":
        st = get_stats(chat_id)
        # Refresh the displayed rate using the latest interval.
        now = time.time()
        elapsed = now - st["last_time"]
        if elapsed > 0:
            st["rate"] = (st["total"] - st["last_total"]) / elapsed
        await query.edit_message_text(
            stats_text(chat_id),
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Обновить", callback_data="stats")],
                [InlineKeyboardButton("◀️ Назад", callback_data="menu")],
            ]),
        )

    elif data == "settings":
        await query.edit_message_text(
            _settings_txt(chat_id),
            reply_markup=settings_keyboard(),
        )

    elif data == "seed_menu":
        await query.edit_message_text(
            f"🔑 <b>Сид-фраза</b>\n\nСейчас: <b>{s['seed_words']} слов</b>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("12 слов", callback_data="seed12"),
                    InlineKeyboardButton("24 слова", callback_data="seed24"),
                ],
                [InlineKeyboardButton("◀️ Назад", callback_data="menu")],
            ]),
        )

    elif data == "case_menu":
        await query.edit_message_text(
            "🔤 <b>Регистр</b>\n\n"
            f"Сейчас: <b>{'включён' if s['case_sensitive'] else 'выключен'}</b>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("ВКЛ", callback_data="caseon"),
                    InlineKeyboardButton("ВЫКЛ", callback_data="caseoff"),
                ],
                [InlineKeyboardButton("◀️ Назад", callback_data="menu")],
            ]),
        )

    elif data == "address_menu":
        await query.edit_message_text(
            "💎 <b>Формат адреса</b>\n\n"
            f"Сейчас: <b>{'EQ (bounceable)' if s['bounceable'] else 'UQ (non-bounceable)'}</b>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("UQ", callback_data="addruq"),
                    InlineKeyboardButton("EQ", callback_data="addreq"),
                ],
                [InlineKeyboardButton("◀️ Назад", callback_data="menu")],
            ]),
        )

    elif data in {"seed12", "seed24", "caseon", "caseoff", "addruq", "addreq"}:
        if data == "seed12":
            s["seed_words"] = 12
            msg = "✅ Сид-фраза: 12 слов"
        elif data == "seed24":
            s["seed_words"] = 24
            msg = "✅ Сид-фраза: 24 слова"
        elif data == "caseon":
            s["case_sensitive"] = True
            msg = "✅ Регистр: включён"
        elif data == "caseoff":
            s["case_sensitive"] = False
            msg = "✅ Регистр: выключен"
        elif data == "addruq":
            s["bounceable"] = False
            msg = "✅ Формат адреса: UQ"
        else:
            s["bounceable"] = True
            msg = "✅ Формат адреса: EQ"

        await query.edit_message_text(
            msg,
            reply_markup=main_menu_keyboard(chat_id),
        )

    elif data == "stop":
        sess = sessions.pop(chat_id, None)
        if sess:
            sess["stop"].set()
            for p in sess["procs"]:
                p.terminate()
                p.join(timeout=2)
            if sess.get("task"):
                sess["task"].cancel()
            msg = "🛑 Поиск остановлен."
        else:
            msg = "ℹ️ Активного поиска нет."

        await query.edit_message_text(
            msg,
            reply_markup=main_menu_keyboard(chat_id),
        )

    elif data == "new_search":
        await query.edit_message_text(
            "🔎 <b>Новый поиск</b>\n\n"
            "Просто отправь паттерн от 1 до 8 символов.\n"
            "Например: <code>MOON</code>",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup([
                [InlineKeyboardButton("◀️ В меню", callback_data="menu")]
            ]),
        )

# ── Handlers ──────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await show_main_menu(update, context)

async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    sess = sessions.pop(chat_id, None)
    if sess:
        sess["stop"].set()
        for p in sess["procs"]:
            p.terminate()
            p.join(timeout=2)
        if sess.get("task"):
            sess["task"].cancel()
        await update.message.reply_text("Поиск остановлен.")
    else:
        await update.message.reply_text("Нет активного поиска.")

async def handle_pattern(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    pattern = update.message.text.strip()

    if not (1 <= len(pattern) <= 8):
        await update.message.reply_text("Паттерн: от 1 до 8 символов.")
        return

    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not all(c in allowed for c in pattern):
        await update.message.reply_text("Только буквы, цифры, - и _ (base64url).")
        return

    # stop old session
    old = sessions.pop(chat_id, None)
    if old:
        old["stop"].set()
        for p in old["procs"]:
            p.terminate()
            p.join(timeout=2)
        if old.get("task"):
            old["task"].cancel()

    s = get_settings(chat_id)
    # Normalise pattern once here so workers don't repeat the work
    search = pattern if s["case_sensitive"] else pattern.upper()

    n = multiprocessing.cpu_count()
    stop = Event()
    q = Queue()
    procs = []
    for i in range(n):
        p = Process(
            target=_worker,
            args=(i, search, q, stop, s["case_sensitive"], s["bounceable"]),
            daemon=True,
        )
        p.start()
        procs.append(p)

    task = asyncio.get_event_loop().create_task(_watch(chat_id, context))
    sessions[chat_id] = {
        "pattern": pattern,
        "procs": procs,
        "stop": stop,
        "q": q,
        "task": task,
        "seed_words": s["seed_words"],
    }

    fmt = "EQ..." if s["bounceable"] else "UQ..."
    case_note = " (регистр важен)" if s["case_sensitive"] else ""
    await update.message.reply_text(
        f"Поиск запущен: ...{pattern}{case_note}\n"
        f"Формат: {fmt}  |  Сид: {s['seed_words']} слов  |  Ядер: {n}\n\n"
        "/stop — остановить"
    )

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if not BOT_TOKEN:
        print("Нет BOT_TOKEN в .env")
        sys.exit(1)

    # Load BIP39 wordlist before starting (blocking, but only once)
    print("Загружаю BIP39 wordlist...")
    ok = _load_wordlist()
    print(f"Wordlist: {'OK ({} слов)'.format(len(_WORDLIST)) if ok else 'ОШИБКА — seed будет в hex'}")

    n = multiprocessing.cpu_count()
    print(f"Запущен | {n} ядер CPU")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CallbackQueryHandler(menu_callback))
    app.add_handler(CommandHandler("stop", cmd_stop))
    app.add_handler(CommandHandler("settings", cmd_settings))
    app.add_handler(CommandHandler("seed12", cmd_seed12))
    app.add_handler(CommandHandler("seed24", cmd_seed24))
    app.add_handler(CommandHandler("caseon", cmd_caseon))
    app.add_handler(CommandHandler("caseoff", cmd_caseoff))
    app.add_handler(CommandHandler("addruq", cmd_addruq))
    app.add_handler(CommandHandler("addreq", cmd_addreq))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_pattern))

    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
