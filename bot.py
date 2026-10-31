# ============================================================
# VIRUSTOTAL TELEGRAM BOT
# Python 3.10+
# Install: pip install -r requirements.txt
# Run:     python bot.py
# ============================================================

import asyncio
import hashlib
import logging
import os
import sqlite3
from datetime import datetime, timezone

import aiohttp
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
)
from telegram.constants import ChatAction
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# -------------------- НАСТРОЙКИ --------------------
# Вставь ключи между кавычками. Не отправляй их никому.
BOT_TOKEN = "9221092240:AAGG2WcClwQVJIHBEvxYqf_yuyvsUsAQ0OY"
VT_API_KEY = "92957b55b2a21073faf68ec72655294fd91bd24ade87e8ffa467f1a33cafdc1f"

# Необязательно: Telegram ID владельца. Узнать можно у @userinfobot.
# Оставь 0, если проверка владельца не нужна.
ADMIN_ID = 7608889836

DB_FILE = "virustotal_bot.sqlite3"
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB — ограничение загрузки через Telegram Bot API
VT_BASE = "https://www.virustotal.com/api/v3"
POLL_SECONDS = 15
MAX_WAIT_SECONDS = 180
# ---------------------------------------------------

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("VirusTotalBot")


def db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            target TEXT NOT NULL,
            malicious INTEGER DEFAULT 0,
            suspicious INTEGER DEFAULT 0,
            harmless INTEGER DEFAULT 0,
            undetected INTEGER DEFAULT 0,
            result TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            first_seen TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def save_user(user_id: int):
    conn = db()
    conn.execute(
        "INSERT OR IGNORE INTO users(user_id, first_seen) VALUES(?, ?)",
        (user_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def save_scan(user_id, kind, target, stats, result):
    conn = db()
    conn.execute(
        """INSERT INTO scans
        (user_id, kind, target, malicious, suspicious, harmless,
         undetected, result, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id, kind, target,
            stats.get("malicious", 0),
            stats.get("suspicious", 0),
            stats.get("harmless", 0),
            stats.get("undetected", 0),
            result,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def get_stats(user_id=None):
    conn = db()
    if user_id is None:
        scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        threats = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE malicious > 0 OR suspicious > 0"
        ).fetchone()[0]
    else:
        scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id=?", (user_id,)
        ).fetchone()[0]
        users = 1
        threats = conn.execute(
            """SELECT COUNT(*) FROM scans
            WHERE user_id=? AND (malicious > 0 OR suspicious > 0)""",
            (user_id,),
        ).fetchone()[0]
    conn.close()
    return scans, users, threats


def get_history(user_id, limit=5):
    conn = db()
    rows = conn.execute(
        """SELECT kind, target, malicious, suspicious, result, created_at
        FROM scans WHERE user_id=? ORDER BY id DESC LIMIT ?""",
        (user_id, limit),
    ).fetchall()
    conn.close()
    return rows


def main_keyboard():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📁 Проверить файл", callback_data="scan_file"),
            InlineKeyboardButton("🔗 Проверить URL", callback_data="scan_url"),
        ],
        [
            InlineKeyboardButton("📊 Моя статистика", callback_data="my_stats"),
            InlineKeyboardButton("🕘 История", callback_data="history"),
        ],
        [InlineKeyboardButton("ℹ️ О VirusTotal", callback_data="about")],
    ])


def back_keyboard():
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("⬅️ Главное меню", callback_data="home")]]
    )


def is_configured():
    return (
        BOT_TOKEN
        and VT_API_KEY
        and not BOT_TOKEN.startswith("ВСТАВЬ_")
        and not VT_API_KEY.startswith("ВСТАВЬ_")
    )


async def vt_request(method, endpoint, *, data=None, headers_extra=None, timeout=90):
    headers = {"x-apikey": VT_API_KEY}
    if headers_extra:
        headers.update(headers_extra)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as session:
        async with session.request(
            method, f"{VT_BASE}{endpoint}", headers=headers, data=data
        ) as response:
            raw = await response.text()
            try:
                payload = await response.json(content_type=None)
            except Exception:
                payload = {"raw": raw}

            if response.status >= 400:
                message = payload.get("error", {}).get("message", raw)
                if response.status == 429:
                    raise RuntimeError(
                        "VirusTotal ограничил частоту запросов (429). "
                        "Подожди немного и попробуй снова."
                    )
                if response.status == 401:
                    raise RuntimeError("VirusTotal отклонил API-ключ (401). Проверь ключ.")
                if response.status == 403:
                    raise RuntimeError(
                        "VirusTotal запретил этот запрос (403). "
                        "Возможно, функция недоступна на твоём тарифе."
                    )
                raise RuntimeError(f"VirusTotal API: HTTP {response.status}: {message}")
            return payload


async def wait_for_analysis(analysis_id):
    elapsed = 0
    while elapsed <= MAX_WAIT_SECONDS:
        payload = await vt_request("GET", f"/analyses/{analysis_id}")
        data = payload.get("data", {})
        attributes = data.get("attributes", {})
        status = attributes.get("status")

        if status == "completed":
            return attributes.get("stats", {})
        if status == "failed":
            raise RuntimeError("VirusTotal не смог завершить анализ.")
        await asyncio.sleep(POLL_SECONDS)
        elapsed += POLL_SECONDS

    raise RuntimeError(
        "Проверка ещё выполняется. Попробуй позже — VirusTotal может "
        "закончить анализ с задержкой."
    )


def format_report(stats, target, kind):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = sum(stats.values()) if stats else 0

    if malicious > 0:
        verdict = "🚨 Обнаружены угрозы"
    elif suspicious > 0:
        verdict = "⚠️ Есть подозрительные срабатывания"
    else:
        verdict = "✅ Обнаружений нет"

    safe_target = target
    if len(safe_target) > 180:
        safe_target = safe_target[:177] + "..."

    return (
        f"🛡 <b>ОТЧЁТ VIRUSTOTAL</b>\n\n"
        f"<b>Объект:</b> <code>{safe_target}</code>\n"
        f"<b>Тип:</b> {kind}\n\n"
        f"<b>{verdict}</b>\n\n"
        f"🔴 Вредоносные: <b>{malicious}</b>\n"
        f"🟠 Подозрительные: <b>{suspicious}</b>\n"
        f"🟢 Безопасные: <b>{harmless}</b>\n"
        f"⚪ Не обнаружено: <b>{undetected}</b>\n"
        f"📊 Всего результатов: <b>{total}</b>\n\n"
        f"<i>Важно: 0 обнаружений не гарантирует абсолютную безопасность.</i>"
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    save_user(user.id)
    context.user_data.pop("waiting_url", None)

    if not is_configured():
        await update.message.reply_text(
            "⚙️ <b>Бот почти готов</b>\n\n"
            "В файле bot.py вставь BOT_TOKEN и VT_API_KEY в блоке настроек, "
            "сохрани файл и перезапусти бота.",
            parse_mode="HTML",
        )
        return

    await update.message.reply_text(
        "🛡 <b>VIRUSTOTAL SCANNER</b>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "Проверяй файлы и ссылки через VirusTotal.\n\n"
        "📁 Отправь файл для анализа или выбери проверку URL.\n"
        "🔍 Результаты поступают из настоящего VirusTotal API.",
        parse_mode="HTML",
        reply_markup=main_keyboard(),
    )


async def show_home(query):
    await query.edit_message_text(
        "🛡 <b>VIRUSTOTAL SCANNER</b>\n"
        "━━━━━━━━━━━━━━━━━━\n"
        "Выбери, что будем проверять.\n\n"
        "📁 Файлы: APK, EXE, ZIP и другие.\n"
        "🔗 Ссылки: проверка URL.",
        parse_mode="HTML",
        reply_markup=main_keyboard(),
    )


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    action = query.data

    if action == "home":
        context.user_data.pop("waiting_url", None)
        await show_home(query)

    elif action == "scan_file":
        context.user_data.pop("waiting_url", None)
        await query.edit_message_text(
            "📁 <b>Отправь файл в этот чат</b>\n\n"
            "Максимальный размер — 20 МБ.\n"
            "После загрузки бот отправит его в VirusTotal на анализ.",
            parse_mode="HTML",
            reply_markup=back_keyboard(),
        )

    elif action == "scan_url":
        context.user_data["waiting_url"] = True
        await query.edit_message_text(
            "🔗 <b>Отправь ссылку для проверки</b>\n\n"
            "Например: https://example.com\n"
            "Отправь полный URL отдельным сообщением.",
            parse_mode="HTML",
            reply_markup=back_keyboard(),
        )

    elif action == "my_stats":
        scans, _, threats = get_stats(query.from_user.id)
        await query.edit_message_text(
            "📊 <b>ТВОЯ СТАТИСТИКА</b>\n\n"
            f"🔍 Проверок: <b>{scans}</b>\n"
            f"⚠️ Проверок с угрозами: <b>{threats}</b>",
            parse_mode="HTML",
            reply_markup=back_keyboard(),
        )

    elif action == "history":
        rows = get_history(query.from_user.id)
        if not rows:
            text = "🕘 <b>История пуста</b>\n\nТы ещё ничего не проверял."
        else:
            lines = ["🕘 <b>ПОСЛЕДНИЕ ПРОВЕРКИ</b>\n"]
            for kind, target, bad, sus, result, created in rows:
                short = target if len(target) < 45 else target[:42] + "..."
                lines.append(
                    f"• <b>{kind}</b>: <code>{short}</code>\n"
                    f"  Вредоносных: {bad} | Подозрительных: {sus}"
                )
            text = "\n\n".join(lines)
        await query.edit_message_text(
            text, parse_mode="HTML", reply_markup=back_keyboard()
        )

    elif action == "about":
        await query.edit_message_text(
            "ℹ️ <b>О ПРОЕКТЕ</b>\n\n"
            "Бот использует официальный VirusTotal API v3.\n"
            "VirusTotal объединяет результаты множества антивирусных движков.\n\n"
            "⚠️ Бесплатный Public API имеет ограничения и не предназначен "
            "для коммерческого использования.\n"
            "Не загружай конфиденциальные файлы: отправленные образцы могут "
            "быть доступны партнёрам VirusTotal.",
            parse_mode="HTML",
            reply_markup=back_keyboard(),
        )


async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.user_data.get("waiting_url"):
        return

    url = (update.message.text or "").strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        await update.message.reply_text(
            "❌ Нужна полная ссылка, начинающаяся с http:// или https://."
        )
        return

    context.user_data.pop("waiting_url", None)
    status = await update.message.reply_text("⏳ Отправляю ссылку в VirusTotal...")
    try:
        payload = await vt_request("POST", "/urls", data={"url": url})
        analysis_id = payload["data"]["id"]
        await status.edit_text("🔍 Ссылка отправлена. Жду результаты анализа...")
        stats = await wait_for_analysis(analysis_id)
        report = format_report(stats, url, "URL")
        save_scan(update.effective_user.id, "URL", url, stats, report)
        await status.edit_text(report, parse_mode="HTML", reply_markup=main_keyboard())
    except Exception as exc:
        log.exception("URL scan failed")
        await status.edit_text(
            f"❌ <b>Не удалось проверить ссылку</b>\n\n{escape_html(str(exc))}",
            parse_mode="HTML",
            reply_markup=main_keyboard(),
        )


def escape_html(value):
    return (
        str(value).replace("&", "&amp;")
        .replace("<", "&lt;").replace(">", "&gt;")
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.message
    document = message.document
    if not document:
        return

    if not is_configured():
        await message.reply_text("Сначала настрой BOT_TOKEN и VT_API_KEY в bot.py.")
        return

    if document.file_size and document.file_size > MAX_FILE_SIZE:
        await message.reply_text("❌ Файл больше 20 МБ. Telegram Bot API не даст скачать его этим ботом.")
        return

    status = await message.reply_text("⏳ Получаю файл...")
    try:
        tg_file = await context.bot.get_file(document.file_id)
        file_bytes = await tg_file.download_as_bytearray()

        if len(file_bytes) > MAX_FILE_SIZE:
            await status.edit_text("❌ Файл больше допустимых 20 МБ.")
            return

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        filename = document.file_name or "uploaded_file"
        await status.edit_text("🛡 Загружаю файл в VirusTotal...")

        form = aiohttp.FormData()
        form.add_field(
            "file",
            bytes(file_bytes),
            filename=filename,
            content_type=document.mime_type or "application/octet-stream",
        )
        payload = await vt_request("POST", "/files", data=form, timeout=180)
        analysis_id = payload["data"]["id"]

        await status.edit_text("🔍 Файл загружен. Ожидаю результаты антивирусов...")
        stats = await wait_for_analysis(analysis_id)
        report = format_report(stats, filename, "Файл")
        report += f"\n\n<code>SHA-256: {sha256}</code>"
        save_scan(message.from_user.id, "Файл", filename, stats, report)
        await status.edit_text(report, parse_mode="HTML", reply_markup=main_keyboard())

    except Exception as exc:
        log.exception("File scan failed")
        await status.edit_text(
            f"❌ <b>Не удалось проверить файл</b>\n\n{escape_html(str(exc))}",
            parse_mode="HTML",
            reply_markup=main_keyboard(),
        )


async def admin_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not ADMIN_ID or update.effective_user.id != ADMIN_ID:
        await update.message.reply_text("⛔ Нет доступа.")
        return
    scans, users, threats = get_stats()
    await update.message.reply_text(
        "👑 <b>АДМИН-СТАТИСТИКА</b>\n\n"
        f"👥 Пользователей: <b>{users}</b>\n"
        f"🔍 Всего проверок: <b>{scans}</b>\n"
        f"⚠️ Проверок с угрозами: <b>{threats}</b>",
        parse_mode="HTML",
    )


async def post_init(application: Application):
    db().close()
    log.info("VirusTotal bot started")


def main():
    if not BOT_TOKEN or BOT_TOKEN.startswith("ВСТАВЬ_"):
        raise SystemExit("Открой bot.py и вставь BOT_TOKEN.")
    if not VT_API_KEY or VT_API_KEY.startswith("ВСТАВЬ_"):
        raise SystemExit("Открой bot.py и вставь VT_API_KEY.")

    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .build()
    )
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("admin", admin_stats))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url)
    )

    log.info("Starting polling...")
    application.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
