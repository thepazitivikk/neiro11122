import json
import os
import random
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
import secrets
import hashlib
import getpass


app = Flask(__name__)

# Глобальные переменные для уведомлений
notification_history = []
manual_notifications = []

app = Flask(__name__)
app.secret_key = 'AYYAYAYYAYAYYPoPuti@YsheEdemKryti'  # Замените на случайный ключ

EMAIL_CONFIG = {
    'smtp_server': 'smtp.mail.ru',
    'smtp_port': 587,
    'email': 'poputisuppor@mail.ru',  # Ваш полный адрес Mail.ru
    'password': 'G0Pd24XqPSFJca6ecNNC'  # Сгенерированный пароль
}

# Хранилище для 2FA кодов
two_factor_codes = {}

def hash_password(password, salt=None):
    """Хеширование пароля с солью"""
    if salt is None:
        salt = secrets.token_hex(16)

    # Создаем хеш с солью
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Количество итераций
    ).hex()

    return f"{salt}${password_hash}"


from urllib.parse import urlencode

# Добавьте эти константы в начало файла после других конфигураций
YANDEX_OAUTH_CONFIG = {
    'client_id': '0ee41df6b4834b65babaee655baa4d86',
    'client_secret': 'ad7a4141e048406e9c170a2b2af804ba',
    'redirect_uri': 'http://localhost:5000/auth/yandex/callback',
    'auth_url': 'https://oauth.yandex.ru/authorize',
    'token_url': 'https://oauth.yandex.ru/token',
    'user_info_url': 'https://login.yandex.ru/info'
}


# Хранилище пользователей
def load_users():
    """Загрузка пользователей из файла"""
    try:
        with open('users.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_users(users):
    """Сохранение пользователей в файл"""
    try:
        with open('users.json', 'w', encoding='utf-8') as f:
            json.dump(users, f, ensure_ascii=False, indent=2)
        print("✅ Пользователи сохранены")
    except Exception as e:
        print(f"❌ Ошибка сохранения пользователей: {e}")


# Добавьте эти маршруты в app.py

@app.route('/auth/yandex')
def auth_yandex():
    """Перенаправление на авторизацию Yandex"""
    params = {
        'response_type': 'code',
        'client_id': YANDEX_OAUTH_CONFIG['client_id'],
        'redirect_uri': YANDEX_OAUTH_CONFIG['redirect_uri'],
        'display': 'popup'
    }
    auth_url = f"{YANDEX_OAUTH_CONFIG['auth_url']}?{urlencode(params)}"
    return redirect(auth_url)


@app.route('/auth/yandex/callback')
def auth_yandex_callback():
    """Обработка callback от Yandex"""
    try:
        code = request.args.get('code')
        error = request.args.get('error')

        if error:
            flash(f'Ошибка авторизации: {error}', 'error')
            return redirect('/')

        if not code:
            flash('Код авторизации не получен', 'error')
            return redirect('/')

        # Получаем access token
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': YANDEX_OAUTH_CONFIG['client_id'],
            'client_secret': YANDEX_OAUTH_CONFIG['client_secret']
        }

        response = requests.post(YANDEX_OAUTH_CONFIG['token_url'], data=token_data)
        token_info = response.json()

        if 'access_token' not in token_info:
            flash('Не удалось получить токен доступа', 'error')
            return redirect('/')

        access_token = token_info['access_token']

        # Получаем информацию о пользователе
        user_response = requests.get(
            YANDEX_OAUTH_CONFIG['user_info_url'],
            headers={'Authorization': f'OAuth {access_token}'}
        )
        user_info = user_response.json()

        # Сохраняем пользователя в системе
        users = load_users()
        yandex_id = user_info['id']

        user_data = {
            'yandex_id': yandex_id,
            'login': user_info.get('login', ''),
            'display_name': user_info.get('display_name', ''),
            'real_name': user_info.get('real_name', ''),
            'first_name': user_info.get('first_name', ''),
            'last_name': user_info.get('last_name', ''),
            'email': user_info.get('default_email', ''),
            'phone': user_info.get('default_phone', {}).get('number', ''),
            'birthday': user_info.get('birthday', ''),
            'avatar_url': f"https://avatars.yandex.net/get-yapic/{user_info.get('default_avatar_id', '')}/islands-200",
            'created_at': datetime.now().isoformat(),
            'last_login': datetime.now().isoformat()
        }

        users[yandex_id] = user_data
        save_users(users)

        # Создаем сессию пользователя
        session['user'] = user_data
        session['user_id'] = yandex_id

        flash(f'Добро пожаловать, {user_data.get("first_name", user_data.get("display_name", "Пользователь"))}!',
              'success')
        print(f"✅ Пользователь вошел через Yandex ID: {user_data['display_name']}")

        return redirect('/')

    except Exception as e:
        print(f"❌ Ошибка авторизации через Yandex: {e}")
        flash('Произошла ошибка при авторизации', 'error')
        return redirect('/')


@app.route('/auth/logout')
def auth_logout():
    """Выход пользователя"""
    session.pop('user', None)
    session.pop('user_id', None)
    flash('Вы успешно вышли из системы', 'info')
    return redirect('/')


@app.route('/user/profile')
def user_profile():
    """Профиль пользователя"""
    user = session.get('user')
    if not user:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect('/')

    return jsonify(user)

def verify_password(password, hashed_password):
    """Проверка пароля"""
    try:
        salt, stored_hash = hashed_password.split('$')
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return new_hash == stored_hash
    except:
        return False


def load_admin_users():
    """Загрузка администраторов из файла"""
    try:
        with open('admins.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Ошибка загрузки администраторов: {e}")
        return {}


def save_admin_users(admin_users):
    """Сохранение администраторов в файл"""
    try:
        with open('admins.json', 'w', encoding='utf-8') as f:
            json.dump(admin_users, f, ensure_ascii=False, indent=2)
        print("✅ Администраторы сохранены")
    except Exception as e:
        print(f"❌ Ошибка сохранения администраторов: {e}")

class AdminSession:
    def __init__(self, email, created_at=None):
        self.email = email
        self.created_at = created_at or datetime.now()
        self.expires_at = self.created_at + timedelta(minutes=15)

    def is_valid(self):
        return datetime.now() < self.expires_at

    def get_remaining_time(self):
        remaining = self.expires_at - datetime.now()
        minutes = max(0, int(remaining.total_seconds() // 60))
        seconds = max(0, int(remaining.total_seconds() % 60))
        return minutes, seconds

    def to_dict(self):
        return {
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat()
        }

    @classmethod
    def from_dict(cls, data):
        try:
            created_at_str = data['created_at']
            # Убираем Z если есть
            if created_at_str.endswith('Z'):
                created_at_str = created_at_str[:-1]
            created_at = datetime.fromisoformat(created_at_str)
            session = cls(data['email'], created_at)
            return session
        except Exception as e:
            print(f"❌ Ошибка создания сессии из dict: {e}")
            # Создаем новую сессию в случае ошибки
            return cls(data['email'])


@app.cli.command('create-admin')
def create_admin_command():
    """Создание нового администратора через консоль"""
    print("👤 Создание нового администратора")
    print("=" * 40)

    email = input("Введите email администратора: ").strip()

    if not email:
        print("❌ Email не может быть пустым")
        return

    # Проверяем существующих администраторов
    admin_users = load_admin_users()

    if email in admin_users:
        print(f"❌ Администратор с email {email} уже существует")
        return

    name = input("Введите имя администратора: ").strip()
    if not name:
        name = "Администратор"

    # Запрашиваем пароль
    while True:
        password = getpass.getpass("Введите пароль: ")
        confirm_password = getpass.getpass("Подтвердите пароль: ")

        if password != confirm_password:
            print("❌ Пароли не совпадают. Попробуйте снова.")
            continue

        if len(password) < 6:
            print("❌ Пароль должен быть не менее 6 символов.")
            continue

        break

    # Запрашиваем финальный мастер-пароль
    master_password = getpass.getpass("Введите финальный мастер-пароль для подтверждения: ")

    # Генерируем правильный хеш от вашего мастер-пароля
    correct_master_password = "_e-p_QKYIazvjRfEsO4hiXx9v-ZNSK"
    expected_master_hash = hashlib.sha256(correct_master_password.encode('utf-8')).hexdigest()

    # Для отладки покажем какой хеш ожидается
    print(f"🔐 Ожидаемый хеш: {expected_master_hash}")

    # Создаем хеш введенного мастер-пароля для проверки
    master_hash = hashlib.sha256(master_password.encode('utf-8')).hexdigest()
    print(f"🔐 Введенный хеш: {master_hash}")

    if master_hash != expected_master_hash:
        print("❌ Неверный мастер-пароль! Создание администратора отменено.")
        print(f"💡 Подсказка: мастер-пароль должен быть: {correct_master_password}")
        return

    # Хешируем пароль администратора
    password_hash = hash_password(password)

    # Создаем запись администратора
    admin_users[email] = {
        'password_hash': password_hash,
        'name': name,
        'created_at': datetime.now().isoformat(),
        'created_by': 'console'
    }

    # Сохраняем
    save_admin_users(admin_users)

    print("✅ Администратор успешно создан!")
    print(f"📧 Email: {email}")
    print(f"👤 Имя: {name}")
    print(f"🕐 Создан: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


@app.cli.command('list-admins')
def list_admins_command():
    """Показать список всех администраторов"""
    admin_users = load_admin_users()

    print("👥 Список администраторов")
    print("=" * 50)

    if not admin_users:
        print("❌ Администраторы не найдены")
        return

    for i, (email, data) in enumerate(admin_users.items(), 1):
        print(f"{i}. {email}")
        print(f"   Имя: {data.get('name', 'Не указано')}")
        print(f"   Создан: {data.get('created_at', 'Неизвестно')}")
        print()


@app.cli.command('delete-admin')
def delete_admin_command():
    """Удаление администратора"""
    admin_users = load_admin_users()

    print("🗑️ Удаление администратора")
    print("=" * 40)

    if not admin_users:
        print("❌ Нет администраторов для удаления")
        return

    print("Доступные администраторы:")
    for i, email in enumerate(admin_users.keys(), 1):
        print(f"{i}. {email}")

    try:
        choice = int(input("Выберите номер администратора для удаления: ")) - 1
        email_to_delete = list(admin_users.keys())[choice]
    except (ValueError, IndexError):
        print("❌ Неверный выбор")
        return

    # Подтверждение
    confirm = input(f"Вы уверены, что хотите удалить {email_to_delete}? (y/N): ")
    if confirm.lower() != 'y':
        print("❌ Удаление отменено")
        return

    # Запрашиваем мастер-пароль
    master_password = getpass.getpass("Введите финальный мастер-пароль для подтверждения: ")
    master_hash = hashlib.sha256(master_password.encode('utf-8')).hexdigest()
    expected_master_hash = "e3d5c0f5b0a896a1b12f4f52c5d6e789b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

    if master_hash != expected_master_hash:
        print("❌ Неверный мастер-пароль! Удаление отменено.")
        return

    # Удаляем
    del admin_users[email_to_delete]
    save_admin_users(admin_users)

    print(f"✅ Администратор {email_to_delete} успешно удален!")

def send_2fa_email(email, code):
    """Отправка кода 2FA на email"""
    try:
        print(f"🔄 Попытка отправки кода {code} на {email}")

        message = MIMEMultipart()
        message['From'] = EMAIL_CONFIG['email']
        message['To'] = email
        message['Subject'] = 'Код подтверждения для входа в админ-панель поПути'

        body = f"""
        <h2>Код подтверждения для входа</h2>
        <p>Ваш код для входа в админ-панель поПути:</p>
        <h1 style="color: #0098E8; font-size: 32px; text-align: center;">{code}</h1>
        <p>Код действителен в течение 10 минут.</p>
        """

        message.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'], timeout=15)
        server.starttls()
        server.login(EMAIL_CONFIG['email'], EMAIL_CONFIG['password'])
        server.send_message(message)
        server.quit()

        print("✅ Письмо успешно отправлено!")
        return True

    except Exception as e:
        print(f"❌ Ошибка отправки email: {e}")
        return False


def require_admin_auth(f):
    """Декоратор для проверки авторизации администратора"""

    def decorated_function(*args, **kwargs):
        if 'admin_session' not in session:
            return redirect(url_for('admin_login'))

        try:
            admin_session_data = session['admin_session']
            admin_session = AdminSession.from_dict(admin_session_data)

            if not admin_session.is_valid():
                session.pop('admin_session', None)
                flash('Сессия истекла. Пожалуйста, войдите снова.', 'error')
                return redirect(url_for('admin_login'))

            # Обновляем сессию в каждом запросе (опционально - для продления сессии)
            session['admin_session'] = admin_session.to_dict()

        except Exception as e:
            print(f"❌ Ошибка проверки сессии: {e}")
            session.pop('admin_session', None)
            flash('Ошибка сессии. Пожалуйста, войдите снова.', 'error')
            return redirect(url_for('admin_login'))

        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


def load_notifications():
    """Загрузка уведомлений из файла"""
    try:
        with open('notifications.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Убедимся, что возвращаем список
            if isinstance(data, list):
                # Автоматически деактивируем просроченные уведомления при загрузке
                for notification in data:
                    expires_at = notification.get('expires_at')
                    if expires_at:
                        try:
                            expires_date = datetime.fromisoformat(expires_at)
                            if datetime.now() > expires_date:
                                notification['active'] = False
                        except:
                            pass
                return data
            elif isinstance(data, dict) and 'notifications' in data:
                return data['notifications']
            else:
                print("⚠️ Неверный формат notifications.json, возвращаем пустой список")
                return []
    except FileNotFoundError:
        print("📁 Файл notifications.json не найден, создаем новый")
        return []
    except Exception as e:
        print(f"❌ Ошибка загрузки уведомлений: {e}")
        return []

def save_notifications(notifications):
    """Сохранение уведомлений в файл"""
    try:
        # Убедимся, что сохраняем как список
        with open('notifications.json', 'w', encoding='utf-8') as f:
            json.dump(notifications, f, ensure_ascii=False, indent=2)
        print("✅ Уведомления успешно сохранены")
    except Exception as e:
        print(f"❌ Ошибка сохранения уведомлений: {e}")

def load_banners():
    """Загрузка баннеров из файла"""
    try:
        with open('banners.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('banners', [])
    except FileNotFoundError:
        return []


def save_banners(banners):
    """Сохранение баннеров в файл"""
    with open('banners.json', 'w', encoding='utf-8') as f:
        json.dump({'banners': banners}, f, ensure_ascii=False, indent=2)


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Загружаем администраторов
        admin_users = load_admin_users()

        print(f"🔐 Попытка входа: {email}")
        print(f"📧 Доступные админы: {list(admin_users.keys())}")

        if email in admin_users:
            stored_hash = admin_users[email]['password_hash']

            if verify_password(password, stored_hash):
                print(f"✅ Пароль верный для {email}")
                code = str(random.randint(100000, 999999))
                two_factor_codes[email] = {
                    'code': code,
                    'expires_at': datetime.now() + timedelta(minutes=10)
                }

                if send_2fa_email(email, code):
                    session['admin_pending'] = email
                    print(f"📧 Код 2FA отправлен на {email}")
                    return redirect(url_for('admin_verify_2fa'))
                else:
                    flash('Ошибка отправки кода на email', 'error')
                    print(f"❌ Ошибка отправки email на {email}")
            else:
                flash('Неверный email или пароль', 'error')
                print(f"❌ Неверный пароль для {email}")
        else:
            flash('Неверный email или пароль', 'error')
            print(f"❌ Email {email} не найден в базе админов")

    return render_template('admin_login.html')

def load_stores():
    """Загрузка магазинов из файла"""
    try:
        with open('stores.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('stores', [])
    except FileNotFoundError:
        # Создаем файл с пустым списком магазинов
        save_stores([])
        return []
    except Exception as e:
        print(f"❌ Ошибка загрузки магазинов: {e}")
        return []

def save_stores(stores):
    """Сохранение магазинов в файл"""
    try:
        with open('stores.json', 'w', encoding='utf-8') as f:
            json.dump({'stores': stores}, f, ensure_ascii=False, indent=2)
        print("✅ Магазины успешно сохранены")
    except Exception as e:
        print(f"❌ Ошибка сохранения магазинов: {e}")

def load_categories():
    """Загрузка категорий из файла"""
    try:
        with open('categories.json', 'r', encoding='utf-8') as f:
            categories = json.load(f)
            return categories[:6]  # Ограничиваем максимум 6 категорий
    except FileNotFoundError:
        # Возвращаем категории по умолчанию
        default_categories = [
            {"name": "Рестораны", "image_url": "/static/images/1.png"},
            {"name": "Аптеки", "image_url": "/static/images/2.png"},
            {"name": "Продукты", "image_url": "/static/images/3.png"},
            {"name": "Косметика", "image_url": "/static/images/6.png"},
            {"name": "Быстрее всего", "image_url": "/static/images/4.png"},
            {"name": "Для детей", "image_url": "/static/images/5.png"}
        ]
        save_categories(default_categories)
        return default_categories
    except Exception as e:
        print(f"❌ Ошибка загрузки категорий: {e}")
        return []

def save_categories(categories):
    """Сохранение категорий в файл"""
    try:
        with open('categories.json', 'w', encoding='utf-8') as f:
            json.dump(categories, f, ensure_ascii=False, indent=2)
        print("✅ Категории успешно сохранены")
    except Exception as e:
        print(f"❌ Ошибка сохранения категорий: {e}")

@app.route('/admin/verify-2fa', methods=['GET', 'POST'])
def admin_verify_2fa():
    if 'admin_pending' not in session:
        print("❌ Нет pending сессии для 2FA")
        return redirect(url_for('admin_login'))

    email = session['admin_pending']
    print(f"🔐 2FA проверка для: {email}")

    if request.method == 'POST':
        code = request.form.get('code')
        print(f"📱 Введенный код: {code}")

        if (email in two_factor_codes and
                two_factor_codes[email]['code'] == code and
                datetime.now() < two_factor_codes[email]['expires_at']):

            print(f"✅ 2FA код верный для {email}")

            # СОЗДАЕМ СЕССИЮ АДМИНИСТРАТОРА - ЭТОГО НЕ ХВАТАЛО!
            admin_session = AdminSession(email)
            session['admin_session'] = admin_session.to_dict()

            # Загружаем имя администратора
            admin_users = load_admin_users()
            session['admin_session']['name'] = admin_users[email]['name']

            # Очищаем временные данные
            session.pop('admin_pending', None)
            del two_factor_codes[email]

            print(f"🎉 Успешный вход! Создана сессия для {email}")
            print(f"📊 Данные сессии: {session['admin_session']}")
            flash('Успешный вход в админ-панель!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            print(f"❌ Неверный или просроченный код 2FA для {email}")
            flash('Неверный или просроченный код', 'error')

    return render_template('admin_verify_2fa.html', email=email)


@app.route('/admin/dashboard')
@require_admin_auth
def admin_dashboard():
    try:
        admin_session = AdminSession.from_dict(session['admin_session'])
        minutes, seconds = admin_session.get_remaining_time()

        notifications = load_notifications()
        banners = load_admin_banners()

        stats = {
            'active_notifications': len([n for n in notifications if n.get('active', True)]),
            'total_banners': len(banners),
            'active_banners': len([b for b in banners if b.get('active', False)]),
            'session_minutes': minutes,
            'session_seconds': seconds,
            'session_percent': int((minutes * 60 + seconds) / (15 * 60) * 100)  # Процент оставшегося времени
        }

        return render_template('admin_dashboard.html', stats=stats)

    except Exception as e:
        print(f"❌ Ошибка в admin_dashboard: {e}")
        flash('Ошибка загрузки панели управления', 'error')
        return redirect(url_for('admin_login'))


@app.route('/admin/notifications', methods=['GET', 'POST'])
@require_admin_auth
def admin_notifications():
    if request.method == 'POST':
        title = request.form.get('title', 'попути')
        message = request.form.get('message')

        if message:
            notifications = load_notifications()

            notification = {
                'id': len(notifications) + 1,
                'title': title,
                'message': message,
                'created_at': datetime.now().isoformat(),
                'expires_at': (datetime.now() + timedelta(minutes=1)).isoformat(),  # Уведомление активно 24 часа
                'sent_by': session['admin_session']['email'],
                'active': True
            }

            notifications.append(notification)
            save_notifications(notifications)

            print(f"📢 УВЕДОМЛЕНИЕ ОТПРАВЛЕНО: {message}")

            flash('Уведомление успешно отправлено! (активно 24 часа)', 'success')
            return redirect(url_for('admin_notifications'))
        else:
            flash('Введите сообщение уведомления', 'error')

    notifications = load_notifications()

    # Фильтруем просроченные уведомления
    valid_notifications = []
    for notification in notifications:
        expires_at = notification.get('expires_at')
        if expires_at:
            try:
                expires_date = datetime.fromisoformat(expires_at)
                if datetime.now() < expires_date:
                    valid_notifications.append(notification)
                else:
                    # Автоматически деактивируем просроченные
                    notification['active'] = False
            except:
                valid_notifications.append(notification)
        else:
            valid_notifications.append(notification)

    # Сохраняем изменения если были деактивированы просроченные
    if len(valid_notifications) != len(notifications):
        save_notifications(notifications)

    recent_notifications = valid_notifications[-10:] if valid_notifications else []

    return render_template('admin_notifications.html', notifications=recent_notifications)


@app.route('/admin/banners', methods=['GET', 'POST'])
@require_admin_auth
def admin_banners():
    try:
        banners = load_admin_banners()

        if request.method == 'POST':
            action = request.form.get('action')

            if action == 'add':
                # Создаем баннер в правильном формате
                banner_type = request.form.get('type', 'image')
                new_banner = {
                    'id': max([b.get('id', 0) for b in banners], default=0) + 1,
                    'title': request.form.get('title', 'Новый баннер'),
                    'description': request.form.get('description', ''),
                    'type': banner_type,
                    'link': request.form.get('link', '#'),
                    'background_color': request.form.get('background_color', '#0098E8'),
                    'text_button': True,  # Всегда True как в ваших баннерах
                    'button_text': request.form.get('button_text', 'Узнать больше'),
                    'active': request.form.get('active') == 'on'
                }

                # Добавляем правильные URL в зависимости от типа
                if banner_type == 'video':
                    new_banner['video_url'] = request.form.get('media_url', '/static/banner-video.mp4')
                else:  # image или по умолчанию
                    new_banner['image_url'] = request.form.get('media_url', '/static/banner1.png')

                banners.append(new_banner)
                save_admin_banners(banners)
                flash('Баннер успешно добавлен!', 'success')

            elif action == 'toggle':
                banner_id = int(request.form.get('banner_id'))
                for banner in banners:
                    if banner['id'] == banner_id:
                        banner['active'] = not banner['active']
                        save_admin_banners(banners)
                        status = 'активирован' if banner['active'] else 'деактивирован'
                        flash(f'Баннер {status}!', 'success')
                        break

            elif action == 'delete':
                banner_id = int(request.form.get('banner_id'))
                banners = [b for b in banners if b['id'] != banner_id]
                save_admin_banners(banners)
                flash('Баннер успешно удален!', 'success')

            return redirect(url_for('admin_banners'))

        return render_template('admin_banners.html', banners=banners)

    except Exception as e:
        print(f"❌ Ошибка в admin_banners: {e}")
        flash('Произошла ошибка при работе с баннерами', 'error')
        return redirect(url_for('admin_banners'))


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_session', None)
    session.pop('admin_pending', None)
    flash('Вы вышли из админ-панели', 'info')
    return redirect(url_for('admin_login'))


@app.route('/get_notification')
def get_notification():
    """Основной endpoint для получения уведомлений"""
    try:
        # Сначала проверяем уведомления из админ-панели
        notifications = load_notifications()
        active_notifications = [n for n in notifications if n.get('active', True)]

        # Берем последнее активное уведомление, которое еще не было показано
        if active_notifications:
            notification = active_notifications[-1]

            # Проверяем, не было ли это уведомление уже показано в этой сессии
            if 'shown_notifications' not in session:
                session['shown_notifications'] = []

            notification_id = notification.get('id')

            # Если уведомление еще не показывалось в этой сессии
            if notification_id not in session['shown_notifications']:
                # Добавляем в список показанных
                session['shown_notifications'].append(notification_id)

                # Помечаем уведомление как показанное (опционально - деактивируем)
                # Если хотим, чтобы уведомление показывалось только один раз:
                # notification['active'] = False
                # save_notifications(notifications)

                return jsonify({
                    'title': notification['title'],
                    'message': notification['message'],
                    'show': True
                })

        # Затем проверяем ручные уведомления (приоритет)
        if manual_notifications:
            notification = manual_notifications.pop(0)
            notification['manual'] = True
            notification['show'] = True
            return jsonify(notification)

        # Проверяем запланированные уведомления
        scheduled_notif = should_show_scheduled_notification()
        if scheduled_notif:
            scheduled_notif['show'] = True
            return jsonify(scheduled_notif)

        # Проверяем умные уведомления
        smart_notif = get_smart_notification()
        if smart_notif:
            smart_notif['show'] = True
            return jsonify(smart_notif)

        # Ничего нет
        return jsonify({
            'show': False,
            'current_time': datetime.now().strftime("%H:%M")
        })

    except Exception as e:
        return jsonify({'error': str(e), 'show': False})

# Умные уведомления по времени
SMART_NOTIFICATIONS = {
    'breakfast': {
        'time_range': ('08:00', '10:00'),
        'chance': 0.3,
        'messages': [
            "☕ Доброе утро! Закажите завтрак со скидкой 20%",
            "🍳 Начните день с вкусного завтрака! Скидка 25% на все утренние блюда",
            "🥐 Свежая выпечка и кофе ждут вас! Бесплатная доставка до 11:00",
            "🍓 Фруктовые завтраки со скидкой 30% только сегодня утром",
            "🥞 Блинчики с вареньем - идеальное начало дня! Всего 199₽",
            "🍳 Яичница с беконом + кофе в подарок при заказе от 400₽",
            "🥪 Сэндвичи на завтрак - быстро, вкусно, полезно! Скидка 15%",
            "🍌 Смузи и гранола - заряд энергии на весь день! Акция до 10:00",
            "🍳 Завтрак в постель? Легко! Доставляем бесплатно до 11:00",
            "🥛 Молочные коктейли + выпечка = идеальное утро! Только 299₽"
        ]
    },
    'lunch': {
        'time_range': ('12:00', '14:30'),
        'chance': 0.3,
        'messages': [
            "🍽️ Время обедать! Скидка 25% на все основные блюда",
            "🥗 Здоровый обед - залог продуктивного дня! Скидка 20% на салаты",
            "🍕 Пицца дня всего за 399₽! Успейте заказать",
            "🍣 Суши сет 'Бизнес-ланч' со скидкой 30% до 15:00",
            "🍔 Бургер + картофель фри + кола = 499₽! Только на обед",
            "🍲 Горячие супы с хлебом - согреют и насытят! Всего 249₽",
            "🥘 Комплексные обеды от 350₽! Бесплатная доставка",
            "🍛 Восточная кухня на обед - wok-боксы со скидкой 25%",
            "🥪 Сэндвичи и супы - идеальный обед в офисе! Акция до 14:00",
            "🍗 Куриные крылышки + соус + напиток = 399₽! Только на обед"
        ]
    },
    'dinner': {
        'time_range': ('17:00', '19:30'),
        'chance': 0.3,
        'messages': [
            "🍕 Идеальный ужин - пицца с семьей! Скидка 30% на всю пиццу",
            "🍣 Романтический ужин? Суши с доставкой на дом! Акция до 20:00",
            "🍔 Бургеры на ужин - почему бы и нет? 2 по цене 1 до 19:00",
            "🥘 Горячие блюда для теплого вечера! Скидка 25% на ужины",
            "🍗 Курочка на ужин - хрустящая и ароматная! Всего 599₽",
            "🍝 Паста с морепродуктами - итальянский вечер дома! Скидка 20%",
            "🌮 Мексиканский ужин - такос и буррито! Акция 'Собери компанию'",
            "🍖 Мангал на дом - шашлык с доставкой! Предзаказ со скидкой 15%",
            "🥗 Легкий ужин - салаты и закуски! Скидка 25% на все салаты",
            "🍤 Морепродукты на ужин - креветки со скидкой 30%!"
        ]
    }
}


def get_current_time_ekb():
    """Получаем текущее время по Екатеринбургу (UTC+5)"""
    # Современный способ - используем timezone.utc
    return datetime.now(timezone.utc)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

def time_in_range(start, end, current):
    """Проверяем, находится ли текущее время в диапазоне"""
    current_time = current.strftime("%H:%M")
    return start <= current_time <= end


def get_smart_notification():
    """Генерирует умное уведомление на основе времени"""
    current_time_utc = get_current_time_ekb()

    for meal_type, config in SMART_NOTIFICATIONS.items():
        start_time, end_time = config['time_range']

        if time_in_range(start_time, end_time, current_time_utc):
            # Проверяем шанс
            if random.random() <= config['chance']:
                message = random.choice(config['messages'])

                # Создаем уведомление
                notification = {
                    'title': 'попути',
                    'message': message,
                    'type': meal_type,
                    'time': current_time_utc.strftime("%H:%M"),
                    'chance_triggered': True,
                    'icon': get_icon_for_meal(meal_type)
                }

                # Логируем для отладки
                print(f"🔔 УМНОЕ УВЕДОМЛЕНИЕ [{meal_type}]: {message}")
                return notification

    return None


def get_icon_for_meal(meal_type):
    """Возвращает иконку для типа приема пищи"""
    icons = {
        'breakfast': '☕',
        'lunch': '🍽️',
        'dinner': '🍕'
    }
    return icons.get(meal_type, '🎁')


def should_show_scheduled_notification():
    """Проверяет запланированное уведомление из notif.json"""
    try:
        json_path = os.path.join(app.root_path, 'static', 'notif.json')
        with open(json_path, 'r', encoding='utf-8') as f:
            notif_data = json.load(f)

        current_time = datetime.now().strftime("%H:%M")

        if current_time == notif_data['show_time']:
            return {
                'title': notif_data.get('title', 'попути'),
                'message': notif_data['message'],
                'type': 'scheduled',
                'time': current_time,
                'scheduled': True
            }
    except Exception as e:
        print(f"Ошибка загрузки scheduled уведомления: {e}")

    return None


# Кастомный фильтр для текста кнопки
@app.template_filter('button_text')
def button_text(banner, default="Узнать больше"):
    return banner.get('button_text', default)




@app.route('/create_notification', methods=['POST'])
def create_manual_notification():
    """Создание ручного уведомления для всех пользователей"""
    try:
        data = request.get_json()

        if not data or 'message' not in data:
            return jsonify({'error': 'Сообщение обязательно'}), 400

        notification = {
            'title': data.get('title', 'попути'),
            'message': data['message'],
            'type': 'manual',
            'time': datetime.now().strftime("%H:%M"),
            'created_by': data.get('author', 'admin'),
            'icon': data.get('icon', '📢')
        }

        # Добавляем в очередь ручных уведомлений
        manual_notifications.append(notification)

        print(f"📢 СОЗДАНО РУЧНОЕ УВЕДОМЛЕНИЕ: {data['message']}")

        return jsonify({
            'status': 'success',
            'message': 'Уведомление создано',
            'notification': notification,
            'queue_size': len(manual_notifications)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/test_chances')
def test_chances():
    """Тестовая страница для проверки шансов уведомлений"""
    results = {}
    current_time = get_current_time_ekb()

    for meal_type, config in SMART_NOTIFICATIONS.items():
        start_time, end_time = config['time_range']
        in_range = time_in_range(start_time, end_time, current_time)

        # Симулируем 100 попыток для статистики
        triggered_count = 0
        for _ in range(100):
            if random.random() <= config['chance']:
                triggered_count += 1

        results[meal_type] = {
            'time_range': f"{start_time} - {end_time}",
            'current_in_range': in_range,
            'chance': config['chance'],
            'simulated_trigger_rate': f"{triggered_count}%",
            'message_count': len(config['messages']),
            'sample_message': random.choice(config['messages'])
        }

    return jsonify({
        'current_time_utc': current_time.strftime("%H:%M"),
        'current_time_ekb': (current_time).strftime("%H:%M"),
        'test_results': results,
        'manual_notifications_in_queue': len(manual_notifications)
    })


@app.route('/admin/notifications')
def notification_admin():
    """Админка для управления уведомлениями"""
    return '''
    <html>
        <head>
            <title>Управление уведомлениями</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { max-width: 800px; margin: 0 auto; }
                .form-group { margin: 15px 0; }
                label { display: block; margin-bottom: 5px; font-weight: bold; }
                input, textarea, select { 
                    width: 100%; padding: 10px; margin: 5px 0; 
                    border: 1px solid #ddd; border-radius: 5px;
                }
                button { 
                    background: #0098E8; color: white; padding: 12px 25px;
                    border: none; border-radius: 5px; cursor: pointer;
                }
                .notification { 
                    background: #f5f5f5; padding: 15px; margin: 10px 0;
                    border-left: 4px solid #0098E8;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📢 Управление уведомлениями</h1>

                <div class="form-group">
                    <h3>Создать ручное уведомление</h3>
                    <form id="notificationForm">
                        <label>Заголовок:</label>
                        <input type="text" name="title" value="попути">

                        <label>Сообщение:*</label>
                        <textarea name="message" rows="3" placeholder="Введите сообщение для всех пользователей..." required></textarea>

                        <label>Автор:</label>
                        <input type="text" name="author" value="admin">

                        <label>Иконка:</label>
                        <select name="icon">
                            <option value="📢">📢 Общее</option>
                            <option value="🎁">🎁 Акция</option>
                            <option value="🚨">🚨 Срочное</option>
                            <option value="❤️">❤️ Спецпредложение</option>
                        </select>

                        <button type="submit">Отправить уведомление всем</button>
                    </form>
                </div>

                <div class="form-group">
                    <h3>Тестирование умных уведомлений</h3>
                    <p><a href="/test_chances" target="_blank">Проверить шансы уведомлений</a></p>
                    <p><a href="/debug_notifications" target="_blank">Отладка системы уведомлений</a></p>
                </div>

                <div id="result"></div>
            </div>

            <script>
                document.getElementById('notificationForm').addEventListener('submit', async function(e) {
                    e.preventDefault();

                    const formData = new FormData(this);
                    const data = Object.fromEntries(formData);

                    try {
                        const response = await fetch('/create_notification', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });

                        const result = await response.json();

                        if (result.status === 'success') {
                            document.getElementById('result').innerHTML = `
                                <div class="notification" style="background: #d4edda; border-color: #28a745;">
                                    <strong>✅ Успех!</strong> Уведомление отправлено в очередь.<br>
                                    <strong>Сообщение:</strong> ${data.message}<br>
                                    <strong>В очереди:</strong> ${result.queue_size} уведомлений
                                </div>
                            `;
                            this.reset();
                        } else {
                            document.getElementById('result').innerHTML = `
                                <div class="notification" style="background: #f8d7da; border-color: #dc3545;">
                                    <strong>❌ Ошибка:</strong> ${result.error}
                                </div>
                            `;
                        }
                    } catch (error) {
                        document.getElementById('result').innerHTML = `
                            <div class="notification" style="background: #f8d7da; border-color: #dc3545;">
                                <strong>❌ Ошибка сети:</strong> ${error}
                            </div>
                        `;
                    }
                });
            </script>
        </body>
    </html>
    '''


@app.route('/debug_notifications')
def debug_notifications():
    """Страница отладки системы уведомлений"""
    current_time = get_current_time_ekb()

    debug_info = {
        'current_time_utc': current_time.strftime("%H:%M"),
        'current_time_ekb': current_time.strftime("%H:%M"),
        'manual_notifications_queue': manual_notifications,
        'notification_history_count': len(notification_history),
        'smart_notifications_config': SMART_NOTIFICATIONS
    }

    return jsonify(debug_info)


def load_admin_banners():
    """Загрузка баннеров из файла для админ-панели"""
    try:
        with open('banners.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Убедимся, что возвращаем список баннеров
            if isinstance(data, dict) and 'banners' in data:
                return data['banners']
            elif isinstance(data, list):
                return data
            else:
                print("⚠️ Неверный формат banners.json, возвращаем пустой список")
                return []
    except FileNotFoundError:
        print("📁 Файл banners.json не найден, возвращаем пустой список")
        return []
    except Exception as e:
        print(f"❌ Ошибка загрузки баннеров: {e}")
        return []


def save_admin_banners(banners):
    """Сохранение баннеров в файл из админ-панели"""
    try:
        # Приводим все баннеры к единому формату
        formatted_banners = []
        for banner in banners:
            formatted_banner = {
                'id': banner.get('id', len(formatted_banners) + 1),
                'title': banner.get('title', 'Новый баннер'),
                'description': banner.get('description', ''),
                'image_url': banner.get('image_url', '/static/banner1.png'),
                'video_url': banner.get('video_url', ''),
                'link': banner.get('link', '#'),
                'background_color': banner.get('background_color', '#0098E8'),
                'text_button': banner.get('text_button', True),
                'type': banner.get('type', 'image'),
                'button_text': banner.get('button_text', 'Узнать больше'),
                'active': banner.get('active', True)
            }
            # Удаляем пустые video_url для image баннеров
            if formatted_banner['type'] == 'image' and not formatted_banner.get('video_url'):
                formatted_banner.pop('video_url', None)
            # Удаляем пустые image_url для video баннеров
            elif formatted_banner['type'] == 'video' and not formatted_banner.get('image_url'):
                formatted_banner.pop('image_url', None)

            formatted_banners.append(formatted_banner)

        with open('banners.json', 'w', encoding='utf-8') as f:
            json.dump({'banners': formatted_banners}, f, ensure_ascii=False, indent=2)
        print("✅ Баннеры успешно сохранены в правильном формате")
    except Exception as e:
        print(f"❌ Ошибка сохранения баннеров: {e}")

# Загружаем категории из JSON-файла
def load_categories():
    try:
        with open('categories.json', 'r', encoding='utf-8') as f:
            categories = json.load(f)
            # Ограничиваем максимум 6 категорий
            return categories[:6]
    except FileNotFoundError:
        # Если файл не найден, возвращаем категории по умолчанию
        return [
            {'name': 'Пицца', 'image_url': '/static/images/pizza.png'},
            {'name': 'Суши', 'image_url': '/static/images/sushi.png'},
            {'name': 'Бургеры', 'image_url': '/static/images/burger.png'},
            {'name': 'Салаты', 'image_url': '/static/images/salad.png'},
            {'name': 'Десерты', 'image_url': '/static/images/dessert.png'},
            {'name': 'Напитки', 'image_url': '/static/images/drink.png'}
        ]
    except Exception as e:
        print(f"Ошибка загрузки категорий: {e}")
        return []


@app.route('/admin/stores', methods=['GET', 'POST'])
@require_admin_auth
def admin_stores():
    """Управление магазинами"""
    try:
        stores = load_stores()
        categories = load_categories()

        if request.method == 'POST':
            action = request.form.get('action')

            if action == 'add':
                # Создаем новый магазин
                new_store = {
                    'id': max([s.get('id', 0) for s in stores], default=0) + 1,
                    'name': request.form.get('name'),
                    'category': request.form.get('category'),
                    'description': request.form.get('description', ''),
                    'image_url': request.form.get('image_url', '/static/images/default-store.jpg'),
                    'delivery_time': request.form.get('delivery_time', '30-40 мин'),
                    'rating': float(request.form.get('rating', 4.5)),
                    'min_order': request.form.get('min_order', '0 ₽'),
                    'delivery_price': request.form.get('delivery_price', 'Бесплатно'),
                    'active': request.form.get('active') == 'on',
                    'created_at': datetime.now().isoformat(),
                    'created_by': session['admin_session']['email']
                }
                # В обработчике добавления магазина (action == 'add')
                tags = []
                tag_texts = request.form.getlist('tag_text[]')
                tag_colors = request.form.getlist('tag_color[]')

                for text, color in zip(tag_texts, tag_colors):
                    if text.strip():  # Только непустые теги
                        tags.append({
                            'text': text.strip(),
                            'color': color
                        })

                new_store['tags'] = tags
                stores.append(new_store)

                save_stores(stores)
                flash('Магазин успешно добавлен!', 'success')

            elif action == 'toggle':
                # Включаем/выключаем магазин
                store_id = int(request.form.get('store_id'))
                for store in stores:
                    if store['id'] == store_id:
                        store['active'] = not store['active']
                        status = 'активирован' if store['active'] else 'деактивирован'
                        flash(f'Магазин {status}!', 'success')
                        break
                save_stores(stores)

            elif action == 'delete':
                # Удаляем магазин
                store_id = int(request.form.get('store_id'))
                stores = [s for s in stores if s['id'] != store_id]
                save_stores(stores)
                flash('Магазин успешно удален!', 'success')

            return redirect(url_for('admin_stores'))

        # Группируем магазины по категориям для отображения
        stores_by_category = {}
        for category in categories:
            category_name = category['name']
            stores_by_category[category_name] = [
                store for store in stores
                if store['category'] == category_name and store.get('active', True)
            ]

        return render_template('admin_stores.html',
                               stores=stores,
                               categories=categories,
                               stores_by_category=stores_by_category)

    except Exception as e:
        print(f"❌ Ошибка в admin_stores: {e}")
        flash('Произошла ошибка при работе с магазинами', 'error')
        return redirect(url_for('admin_stores'))


@app.route('/user/orders')
def user_orders():
    """Страница заказов пользователя"""
    if 'user' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect('/')

    # Здесь можно добавить логику для получения заказов пользователя
    return render_template('user_orders.html', user=session['user'])


@app.route('/user/favorites')
def user_favorites():
    """Страница избранного пользователя"""
    if 'user' not in session:
        flash('Пожалуйста, войдите в систему', 'error')
        return redirect('/')

    # Здесь можно добавить логику для получения избранного
    return render_template('user_favorites.html', user=session['user'])

@app.route('/')
def home():
    banners = load_banners()
    categories = load_categories()
    stores = load_stores()  # Эта функция должна загружать ваши магазины

    # ВРЕМЕННЫЙ КОД ДЛЯ ОТЛАДКИ - потом удалите
    print("=== ДЕБАГ ИНФОРМАЦИЯ ===")
    print(f"Загружено магазинов: {len(stores)}")
    for store in stores:
        print(f"Магазин: {store['name']}, Категория: {store['category']}, Активный: {store.get('active', True)}")
    print("========================")

    # Группируем магазины по категориям для отображения
    stores_by_category = {}
    for category in categories:
        category_name = category['name']
        stores_by_category[category_name] = [
            store for store in stores
            if store['category'] == category_name and store.get('active', True)
        ]
        print(f"В категории '{category_name}': {len(stores_by_category[category_name])} магазинов")

    return render_template('index.html',
                           banners=banners,
                           categories=categories,
                           stores_by_category=stores_by_category)


@app.cli.command('test-notifications')
def test_notifications_command():
    """Консольная команда для тестирования уведомлений"""
    import time
    from datetime import datetime

    print("🧪 Тестирование системы уведомлений...")
    print("=" * 50)

    # Тестируем для каждого типа приема пищи
    for meal_type in ['breakfast', 'lunch', 'dinner']:
        print(f"\n📊 Тестирование {meal_type}:")
        print(f"Время: {SMART_NOTIFICATIONS[meal_type]['time_range']}")
        print(f"Шанс: {SMART_NOTIFICATIONS[meal_type]['chance'] * 100}%")

        # Симулируем 20 попыток
        triggered = 0
        for i in range(20):
            if random.random() <= SMART_NOTIFICATIONS[meal_type]['chance']:
                triggered += 1
                message = random.choice(SMART_NOTIFICATIONS[meal_type]['messages'])
                print(f"  ✅ Попытка {i + 1}: СРАБОТАЛО - {message}")
            else:
                print(f"  ❌ Попытка {i + 1}: не сработало")

        print(f"📈 Итог: {triggered}/20 ({triggered / 20 * 100:.1f}%)")


if __name__ == '__main__':
    print("🚀 Запуск сервиса с умными уведомлениями...")
    print("📊 Доступные команды:")
    print("  • flask test-notifications - тест шансов уведомлений")
    print("  • http://localhost:5000/admin/notifications - админка уведомлений")
    print("  • http://localhost:5000/test_chances - тест шансов в реальном времени")
    print("  • http://localhost:5000/debug_notifications - отладка системы")

    app.run(debug=True)