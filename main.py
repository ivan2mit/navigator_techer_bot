import logging
import time
import requests
import json
from dotenv import load_dotenv
import os
import re
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.helpers import escape_markdown
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    ConversationHandler,
    CallbackQueryHandler,
)


# Файл для хранения данных
DATA_FILE = 'user_data.json'


# --- Сохранить всех пользователей в файл ---
def save_user_data():
    data_to_save = {}
    for user_id, data in user_data.items():
        # Убедимся, что encrypted_password — bytes
        enc_pass = data['encrypted_password']
        if isinstance(enc_pass, str):
            # Если вдруг стал str — это ошибка, но перестрахуемся
            logger.warning(f"Пароль пользователя {user_id} — строка, а не bytes")
            enc_pass_str = enc_pass
        else:
            # Основной путь: bytes → str
            enc_pass_str = enc_pass.decode('utf-8')

        data_to_save[str(user_id)] = {
            'email': data['email'],
            'encrypted_password': enc_pass_str,
            'last_login': data['last_login'].isoformat() if data['last_login'] else None
        }

    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data_to_save, f, ensure_ascii=False, indent=2)
# --- Загрузить пользователей из файла ---
def load_user_data():
    if not os.path.exists(DATA_FILE):
        return {}

    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        if not content:
            return {}
        data = json.loads(content)

    loaded = {}
    for user_id_str, user_info in data.items():
        user_id = int(user_id_str)
        # 🔹 Пароль: str → bytes
        enc_pass = user_info['email']  # ❌ ОШИБКА: ты читаешь login как пароль?
        # Правильно:
        enc_pass_bytes = user_info['encrypted_password'].encode('utf-8')

        # 🔹 Дата: str → datetime
        last_login_dt = None
        if user_info.get('last_login'):
            try:
                last_login_dt = datetime.fromisoformat(user_info['last_login'])
            except ValueError:
                logger.warning(f"Неверный формат даты для {user_id}")
                last_login_dt = None

        loaded[user_id] = {
            'email': user_info['email'],  # или 'email' — смотри, как в JSON
            'encrypted_password': enc_pass_bytes,
            'last_login': last_login_dt,  # ← datetime, а не str
            'session': None
        }
    return loaded

# --- Настройки ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


# Ключ шифрования (должен быть ровно 32 байта, base64-encoded)
# Сгенерировать один раз: from cryptography.fernet import Fernet; print(Fernet.generate_key())
# Загружаем переменные из .env
load_dotenv()
# Получаем ключ
key_str = os.getenv("FERNET_KEY")
FERNET_KEY = os.getenv("FERNET_KEY")
fernet = Fernet(FERNET_KEY)

# === НАСТРОЙКИ ===
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")  # ← Заменить
BASE_URL = os.getenv("BASE_URL")

# URL сайта
LOGIN_URL =BASE_URL+'api/user/login'
CHECK_URL = BASE_URL+'api/rest/order'
ENDPOINT_PARENT = BASE_URL+'api/rest/siteuser/{user_id}'
ORDER_URL = BASE_URL+'admin/#requests/edit/{order_id}'
KID_URL = BASE_URL+'api/rest/kid'
EVENT_URL = BASE_URL+'api/rest/events' # запрос данных по программе(названиеб возраст ссылка)
EVENTGROUP_URL = BASE_URL+'api/rest/eventGroups' # данные о группах в рамках программы
EVENTGROUPSCHEDULE_URL = BASE_URL+'api/rest/eventGroupSchedule'
# Заголовки, имитирующие браузер
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    "X-Requested-With": "XMLHttpRequest",
    'Content-Type': "application/json; charset=utf-8",
    'Accept': 'application/json',
}

STATUS_MAP = {
    "initial":   "🆕 Новая",
    "pause":     "⏸️ Отложена",
    "approve":   "✅ Подтверждена",
    "cancel":    "❌ Отменена",
    "study":     "🎓 Обучается",
}

WEEKDAYS_MAP = {
    1: 'ПН',
    2: 'ВТ',
    3: 'СР',
    4: 'ЧТ',
    5: 'ПТ',
    6: 'СБ',
    0: 'ВС'
}

# Состояния диалога
LOGIN, PASSWORD = range(2)
# Состояния
LOGIN, PASSWORD, FIO, WAITING_FOR_COMMENT = range(4)

# Хранилище пользователей (в реальности — лучше БД)
user_data = {}  # {user_id: {email, encrypted_password, session, last_login}}


# --- Шифрование пароля ---
def encrypt_password(password: str) -> bytes:
    return fernet.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes) -> str:
    return fernet.decrypt(encrypted_password).decode()


# --- Создание авторизованной сессии ---
def create_authenticated_session(email: str, password: str) -> requests.Session | None:
    session = requests.Session()
    session.headers.update(HEADERS)

    try:
        response = session.post(LOGIN_URL, json={'email': email, 'password': password}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            token = data["data"]["access_token"]
            if not token:
                logger.warning("Токен не получен")
                return None
            session.headers['Authorization'] = f'Bearer {token}'
            logger.info("✅ Сессия создана, токен установлен")
            return session
        logger.warning(f"❌ Ошибка входа: {response.status_code} — {response.text}")
    except Exception as e:
        logger.error(f"❌ Ошибка подключения: {e}")
    return None


# --- Умное уведомление (не чаще раза в 30 минут) ---
_last_error_time = {}


# --- Диалог регистрации ---
# async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
#     user_id = update.effective_user.id

#        # Проверяем, есть ли ФИО
#     if 'fio' not in user_data[user_id] or not user_data[user_id]['fio']:
#         await update.message.reply_text("📝 Введите ваше ФИО (для комментариев):")
#         return FIO

#     if user_id in user_data:
#         await update.message.reply_text("Вы уже зарегистрированы. Проверка запущена.")
#         return ConversationHandler.END

#     await update.message.reply_text("🔐 Введите логин:")
#     return LOGIN

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    if user_id not in user_data:
        await update.message.reply_text("🔐 Введите логин:")
        return LOGIN

    # Проверяем, есть ли ФИО
    if 'fio' not in user_data[user_id] or not user_data[user_id]['fio']:
        await update.message.reply_text("📝 Введите ваше ФИО (для комментариев):")
        return FIO

    await update.message.reply_text("Вы уже зарегистрированы.")
    return ConversationHandler.END

async def login_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    email = update.message.text.strip()
    context.user_data["temp_email"] = email
    await update.message.reply_text("🔑 Введите пароль (сообщение будет удалено):")
    return PASSWORD

async def fio_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    fio = update.message.text.strip()

    if user_id in user_data:
        user_data[user_id]['fio'] = fio

    await update.message.reply_text(f"✅ ФИО сохранено: {fio}\nПроверка запущена.")
    return ConversationHandler.END

async def password_received(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    password = update.message.text
    email = context.user_data["temp_email"]

    # Удаляем сообщение с паролем
    try:
        await context.bot.delete_message(chat_id=update.message.chat_id, message_id=update.message.message_id)
    except Exception as e:
        logger.warning(f"Не удалось удалить сообщение: {e}")

    # Шифруем пароль
    try:
        encrypted_password = encrypt_password(password)
    except Exception as e:
        logger.error(f"Ошибка шифрования: {e}")
        await update.message.reply_text("Ошибка шифрования. Попробуйте снова.")
        return ConversationHandler.END

    # Пробуем войти
    session = create_authenticated_session(email, password)
    if not session:
        await update.message.reply_text("❌ Ошибка входа. Проверьте логин и пароль.")
        return ConversationHandler.END

    # Сохраняем
    user_data[user_id] = {
        "email": email,
        "fio": context.user_data.get("temp_fio", "Без ФИО"),  
        "encrypted_password": encrypted_password,
        "session": session,
        "last_login": datetime.now(),
    }

    save_user_data()
    await update.message.reply_text("✅ Успешно! Проверка заявок запущена (каждые 5 мин).")

    return ConversationHandler.END

def create_action_buttons(order_id: int):
    keyboard = [
        [
            InlineKeyboardButton("✅ Подтвердить", callback_data=f"action:{order_id}:approve"),
            InlineKeyboardButton("⏸️ Отложить", callback_data=f"action:{order_id}:pause"),
            InlineKeyboardButton("❌ Отменить", callback_data=f"action:{order_id}:cancel")
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

async def list_applications(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    # Проверяем, зарегистрирован ли пользователь
    if user_id not in user_data:
        await update.message.reply_text("❌ Вы не зарегистрированы. Используйте /start.")
        return

    user = user_data[user_id]
    session = user["session"]
    email = user["email"]
    encrypted_password = user["encrypted_password"]


    async def get_parent(id):
        try:
            URL = ENDPOINT_PARENT.format(user_id = id)
            # TODO передать парам
            response = session.get(URL, params={'_dc': int(time.time() * 1000)}, timeout=10)
            if response.status_code == 200:
                return response.json()['data']
            else:
                raise Exception(f'не удалось получить данные родителя {response.status_code}')
        except Exception as e:
            logger.error(f"Ошибка при ручной проверке: {e}")
            await update.message.reply_text("⚠️ Не удалось подключиться к сайту. Попробуйте позже.")


    async def get_event_group(id):
        try:
            URL = EVENTGROUP_URL
            params = {
                'format': 'mini',
                '_dc': int(time.time() * 1000),
                'id': {id},
                'page': '1',
                'start':'0',
                'length':'100'
            }
            # TODO передать парам
            response = session.get(URL, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()['data']
            else:
                raise Exception(f'не удалось получить данные группы {response.status_code}')
        except Exception as e:
            logger.error(f"Ошибка при ручной проверке: {e}")
            await update.message.reply_text("⚠️ Не удалось подключиться к сайту. Попробуйте позже.")


    async def get_event_group_schedule(id):
        try:
            URL = EVENTGROUPSCHEDULE_URL
            str_id = str(id)
            params = {
                '_dc': int(time.time() * 1000),
                'page': '1',
                'start':'0',
                'length':'25',
                'extFilters': '[{"property":"group_id","value":"'+f'{id}'+'"}]'
            }
            # TODO передать парам
            response = session.get(URL, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()['data']
            else:
                raise Exception(f'не удалось получить данные расписания группы {response.status_code}')
        except Exception as e:
            logger.error(f"Ошибка при ручной проверке: {e}")
            await update.message.reply_text("⚠️ Не удалось подключиться к сайту. Попробуйте позже.")


    async def get_orders():
        apps = response.json()["data"]
        if apps:
            for order in apps:
                parent = await get_parent(order['site_user_id'])
                event_group = await get_event_group(order['group_id'])
                group_schedule = await get_event_group_schedule(order['group_id'])
                # Статус заявки ссылка
                # Название группы дни обучения
                # Заявитель: фио, номер, ссылка
                # Ученик: ФИ, возраст
                # Статусы СНИЛС АДРЕСС школа
                if parent is not None:
                    phone: str = parent[0]['phone']
                    clear_phone = phone.replace('(','').replace(')','').replace('-','').replace(' ','')
                    phone = escape_markdown(phone, version=2)
                    clear_md_phone = escape_markdown(clear_phone, version=2)
                link_order = ORDER_URL.format(order_id = order['id'])
                status = order['state']
                status = escape_markdown(STATUS_MAP[status],2)
                event_name = escape_markdown(event_group[0]['name'],2)
                event_schedule = ''
                for days in group_schedule:
                    event_schedule += ', '.join([WEEKDAYS_MAP[day] for day in days['week_days']])
                    event_schedule += escape_markdown(' ' + days['time_start']+'-'+days['time_end'],2)+'\n'
                parent_fio = escape_markdown(order['site_user_fio'],2)
                link_tg = escape_markdown(f't.me/{clear_phone}',2)

                text = (f'{status} [Перейти к заявке]({link_order})\n'
                        f'{event_name}\n'
                        f'{event_schedule}\n'
                        f'*Ученик:* {order['kid_last_name']} {order['kid_first_name']}\n'
                        f'*Родитель:* {parent_fio} {clear_md_phone}\n'
                        f'{ link_tg}')
                #text = escape_markdown(text, version=2)
                reply_markup = create_action_buttons(order['id'])

                reply_markup = None
                # if order['state'] == "initial":  # или status == "Новая", смотри, что приходит
                #     reply_markup = create_action_buttons(order['id'])

                await update.message.reply_text(text, reply_markup=reply_markup, parse_mode='MarkdownV2')
        else:
            await update.message.reply_text("📭 Нет активных заявок.")
        return

    try:
        # Пробуем получить заявки
        params = {'_dc': int(time.time() * 1000),  # Текущее время в миллисекундах
                'page': 1,
                'start': 0,
                'length': 150,
                'extFilters': '[{"property":"fact_academic_year_id","value":2025,"comparison":"eq"}]'
                }
        response = session.get(CHECK_URL, params=params, timeout=10)
        if response.status_code == 200:
            await get_orders()
        elif response.status_code == 401:
            # Токен просрочен — перелогинимся
            await update.message.reply_text("🔄 Сессия устарела, выполняю повторный вход...")
            try:
                password = decrypt_password(encrypted_password)
            except Exception as e:
                logger.error(f"Ошибка расшифровки: {e}")
                await update.message.reply_text("🔒 Ошибка доступа. Перерегистрируйтесь.")
                return

            new_session = create_authenticated_session(email, password)
            if new_session:
                user["session"] = new_session
                user["last_login"] = datetime.now()
                # Повторяем запрос
                retry_response = new_session.get(CHECK_URL, timeout=10)
                if retry_response.status_code == 200:
                    get_orders()
                else:
                    await update.message.reply_text("❌ Не удалось получить данные после повторного входа.")
            else:
                await update.message.reply_text("❌ Не удалось войти. Проверьте логин/пароль.")
        else:
            await update.message.reply_text(f"⚠️ Ошибка сайта: {response.status_code}")
    except Exception as e:
        logger.error(f"Ошибка при ручной проверке: {e}")
        await update.message.reply_text("⚠️ Не удалось подключиться к сайту. Попробуйте позже.")

async def send_approval_comment(query: Update.callback_query, context: ContextTypes.DEFAULT_TYPE, user_id: int, order_id: int, comment_suffix: str):
    # Чтобы не передавать update
    chat_id = query.message.chat_id
    message_id = query.message.message_id

    # Формируем комментарий
    date_str = datetime.now().strftime("%d.%m")
    fio = user_data[user_id].get('fio', 'Не указано')
    comment = f"{date_str} {fio} {comment_suffix}"

    # Восстанови сессию при необходимости
    session = user_data[user_id]['session']
    if session is None:
        try:
            password = decrypt_password(user_data[user_id]['encrypted_password'])
            session = create_authenticated_session(user_data[user_id]['email'], password)
            if not session:
                await query.edit_message_text("❌ Не удалось восстановить сессию.")
                return
            user_data[user_id]['session'] = session
        except Exception as e:
            logger.error(f"Ошибка восстановления: {e}")
            await query.edit_message_text("🔒 Ошибка доступа.")
            return

    # Отправляем на сервер
    url = f"https://techdo.sirius-ft.ru/api/rest/order/{order_id}/approve"
    payload = {"comment": comment}

    try:
        # response = session.post(url, json=payload, timeout=10)
        if True or response.status_code == 200:
            # ✅ Успех: редактируем ТО ЖЕ сообщение
            current_text = query.message.text
            updated_text = re.sub(
                r'^(🆕|⏸️|✅|❌|🎓)[^\n]*\n',
                "✅ Подтверждена\n",
                current_text,
                count=1,
                flags=re.MULTILINE
            )
            await query.edit_message_text(
                text=updated_text,
                reply_markup=None
                # parse_mode не указываем!
            )
        else:
            # ❌ Ошибка: возвращаем кнопки
            keyboard = create_action_buttons(order_id)
            await query.edit_message_text(
                text=current_text + "\n\n⚠️ Ошибка: не удалось подтвердить.",
                reply_markup=keyboard
                # parse_mode не указываем
            )
    except Exception as e:
        logger.error(f"Ошибка при подтверждении: {e}")
        keyboard = create_action_buttons(order_id)
        await query.edit_message_text(
            text=query.message.text + "\n\n❌ Не удалось подключиться.",
            reply_markup=keyboard
        )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id

    # Проверяем, ожидаем ли комментарий
    if 'pending_approval' in context.user_data:
        order_id = context.user_data.pop('pending_approval')
        custom_comment = update.message.text.strip()

        await send_approval_comment(update, context, user_id, order_id, custom_comment)

# async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
#     query = update.callback_query
#     await query.answer()

#     data = query.data  # action:12345:approve
#     if not data.startswith("action:"):
#         return

#     try:
#         _, order_id, action = data.split(":")
#         order_id = int(order_id)
#         user_id = query.from_user.id

#         # Получаем текущий текст
#         current_text = query.message.text

#         # Меняем кнопки на "ожидание"
#         waiting_markup = InlineKeyboardMarkup([[
#             InlineKeyboardButton("⏳ Выполняется...", callback_data="wait")
#         ]])
#         await query.edit_message_reply_markup(reply_markup=waiting_markup)

#         # Выполняем запрос
#         #success = await send_action_request(user_id, order_id, action)
#         success = 1

#         # Новый статус
#         new_status = STATUS_MAP.get(action, "🔄 Неизвестно")

#         # Обновляем текст: заменяем статус
#         import re
#         updated_text = re.sub(
#             r'^(🆕|⏸️|✅|❌|🎓)[^\n]*\n|(?<=\n)(🆕|⏸️|✅|❌|🎓)[^\n]*\n',
#             f"{new_status}\n",
#             current_text,
#             count=1,
#             flags=re.MULTILINE
#         )

#         if success:
#             # ✅ Успех: обновляем текст, убираем кнопки
#             await query.edit_message_text(
#                 text=updated_text,
#                 reply_markup=None
#             )
#         else:
#             # ❌ Ошибка: возвращаем исходные кнопки
#             original_buttons = create_action_buttons(order_id)  # твоя функция
#             await query.edit_message_text(
#                 text=current_text + "\n\n⚠️ Не удалось выполнить. Попробуйте снова.",
#                 reply_markup=original_buttons
#             )

#     except Exception as e:
#         logger.error(f"Ошибка при обработке кнопки: {e}")
#         # В случае ошибки в коде — возвращаем кнопки
#         try:
#             order_id = int(data.split(":")[1])
#             original_buttons = create_action_buttons(order_id)
#             await query.edit_message_text(
#                 text=query.message.text + "\n\n❌ Ошибка. Попробуйте позже.",
#                 reply_markup=original_buttons,
#                 parse_mode='MarkdownV2'
#             )
#         except:
#             await query.edit_message_text(
#                 text=query.message.text + "\n\n❌ Ошибка.",
#                 reply_markup=None
#             )
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Этот объект знает под каким сообщением была нажата кнопка и что мы передали в сообщении
    query = update.callback_query
    await query.answer()

    data = query.data.split(':')

    button = data[0]
    if button == 'action':
        _, order_id, action = data
        user_id = query.from_user.id
    
        

        if user_id not in user_data:
            await query.edit_message_text("❌ Сессия устарела.")
            return
    order_id = data[1]

    # Сохраняем, что пользователь хочет подтвердить заявку
    if button == "action" and action == "approve":
        # Клавиатура выбора типа
        keyboard = [
            [
                InlineKeyboardButton("✅ Платно", callback_data=f"confirm:{order_id}:платно"),
                InlineKeyboardButton("🏛 Субсидия", callback_data=f"confirm:{order_id}:субсидия"),
            ],
            [
                InlineKeyboardButton("✏️ Другое", callback_data=f"custom:{order_id}")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_reply_markup(reply_markup=reply_markup)

    elif button == "confirm":
        # Уже выбран тип
        _, order_id, comment_type = data.split(":", 2)
        await send_approval_comment(update, context, user_id, int(order_id), comment_type)

    elif button == "custom":
        # Просим ввести свой комментарий
        context.user_data['pending_approval'] = order_id
        await query.edit_message_text(
            "🖋 Введите комментарий (например, 'бюджет', 'грант' и т.п.):"
        )
    # else:
    #     # Другие действия (pause, cancel) — как раньше
    #     await handle_simple_action(query, user_id, order_id, action)

# --- Обработчик ошибок ---
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Ошибка: {context.error}")

def restore_all_sessions():
    for user_id, user in user_data.items():
        if user['session'] is None:
            try:
                password = decrypt_password(user['encrypted_password'])
                session = create_authenticated_session(user['email'], password)
                if session:
                    user['session'] = session
                    user['last_login'] = datetime.now()
                    logger.info(f"Сессия восстановлена для {user_id}")
            except Exception as e:
                logger.error(f"Не удалось восстановить сессию для {user_id}: {e}")

# === Запуск бота ===
def main():
    global user_data
    user_data = load_user_data()  # 🔁 Загружаем данные при старте
    print(f"Загружено пользователей: {len(user_data)}")

    application = Application.builder().token(BOT_TOKEN).build()
    restore_all_sessions()
    # Диалог регистрации
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            LOGIN: [MessageHandler(filters.TEXT & ~filters.COMMAND, login_received)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, password_received)],
            FIO: [MessageHandler(filters.TEXT & ~filters.COMMAND, fio_received)],
        },
        fallbacks=[],
    )

    application.add_handler(conv_handler)
    application.add_error_handler(error_handler)
    application.add_handler(CommandHandler("list", list_applications))
    application.add_handler(CallbackQueryHandler(button_handler))
    # application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("🤖 Бот запущен")

    import atexit
    atexit.register(save_user_data)
    application.run_polling()


if __name__ == "__main__":
    main()