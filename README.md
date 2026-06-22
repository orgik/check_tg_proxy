# TG Proxy Checker

Web-приложение для диагностики Telegram MTProto прокси. Вставьте ссылку на прокси — получите полный отчёт о доступности, TLS-отпечатках, сертификате, стабильности, DPI-фильтрации и DNS.

**Demo:** http://194.87.110.184/

![Dark theme UI](https://img.shields.io/badge/theme-dark-1e293b) ![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue) ![FastAPI](https://img.shields.io/badge/fastapi-0.115-green)

## Возможности

### Проверки
- **TCP/TLS** — подключение с замером RTT
- **TLS-отпечатки** — отправка реальных ClientHello от Chrome, Firefox, Safari, curl с проверкой ServerHello
- **TLS-сертификат** — subject, issuer, срок действия, версия TLS, cipher suite, совпадение SNI
- **Стабильность** — 10 подключений подряд, % успеха, джиттер, определение паттерна (стабильно / rate-limited / заблокировано)
- **DPI-детекция** — фильтрация по SNI, HTTP-проба (маскировка под веб-сервер), обнаружение TCP RST
- **DNS-проверка** — резолв через системный, Google (8.8.8.8), Cloudflare (1.1.1.1), проверка согласованности
- **GeoIP** — страна, город, провайдер, ASN, тип (датацентр/резидентный), reverse DNS

### Инфраструктура
- Очередь на `asyncio.Semaphore` (до 5 одновременных проверок)
- WebSocket для real-time обновлений, fallback на polling
- Админ-панель с историей проверок, статистикой, сменой пароля
- Переключатель языка RU/EN
- Тёмная тема, адаптивный дизайн
- Поддержка форматов secret: hex и base64
- Предупреждение когда сервер блокирует датацентровые IP

## Стек

| Компонент | Технология |
|-----------|-----------|
| Backend | Python, FastAPI, asyncio |
| Frontend | HTML, CSS, vanilla JS |
| БД | SQLite (aiosqlite) |
| TLS-пакеты | scapy (парсинг/патчинг ClientHello) |
| Авторизация | JWT (python-jose) |
| Деплой | nginx, systemd, uvicorn |

## Установка

### Требования
- Ubuntu 22.04+ (или другой Linux)
- Python 3.12+
- nginx

### 1. Клонирование

```bash
git clone https://github.com/orgik/check_tg_proxy.git
cd check_tg_proxy
```

### 2. Установка зависимостей

```bash
apt update
apt install -y python3 python3-venv python3-dev build-essential nginx libffi-dev libssl-dev git

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. ClientHello файлы

Бинарные файлы TLS ClientHello от разных браузеров (из проекта [tls_handshake_check](https://github.com/izmmisha/tls_handshake_check)):

```bash
cd /tmp
git clone --depth 1 https://github.com/izmmisha/tls_handshake_check.git
cp -r tls_handshake_check/client_hello/* /путь/к/check_tg_proxy/app/client_hello/
```

### 4. Конфигурация

```bash
cp .env.example .env
nano .env
```

```env
ADMIN_PASSWORD=ваш_пароль
SECRET_KEY=случайная_строка_32_символа
DATABASE_PATH=./data/cheker.db
MAX_CONCURRENT_CHECKS=5
CHECK_TIMEOUT=30
```

Сгенерировать `SECRET_KEY`:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Запуск (для теста)

```bash
mkdir -p data
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Откройте `http://your-ip:8000/`

### 6. Продакшн (systemd + nginx)

**systemd сервис:**

```bash
cp deploy/cheker.service /etc/systemd/system/
# Отредактируйте пути в файле если нужно
nano /etc/systemd/system/cheker.service

systemctl daemon-reload
systemctl enable cheker
systemctl start cheker
```

**nginx:**

```bash
cp deploy/nginx.conf /etc/nginx/sites-available/cheker
# Замените server_name на свой IP или домен
nano /etc/nginx/sites-available/cheker

ln -sf /etc/nginx/sites-available/cheker /etc/nginx/sites-enabled/cheker
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx
```

### 7. Автоматический деплой

Для деплоя с локальной машины через SSH (требуется `paramiko`):

```bash
pip install paramiko
# Отредактируйте HOST, USER, PASSWORD в deploy/deploy.py
python deploy/deploy.py
```

## Использование

### Главная страница (`/`)
Вставьте ссылку на прокси в любом формате:
```
tg://proxy?server=example.com&port=443&secret=ee...
https://t.me/proxy?server=example.com&port=443&secret=ee...
```

### Админ-панель (`/admin`)
- Логин по паролю из `.env`
- История всех проверок с фильтрацией и поиском
- Смена пароля (сохраняется в БД)

### API

```bash
# Запустить проверку
curl -X POST /api/check \
  -H "Content-Type: application/json" \
  -d '{"proxy_link": "tg://proxy?server=...&port=443&secret=..."}'

# Получить статус
curl /api/status/{task_id}

# WebSocket (real-time)
ws://host/ws/check/{task_id}
```

## Структура проекта

```
├── app/
│   ├── main.py              # FastAPI приложение
│   ├── config.py            # Настройки из env
│   ├── database.py          # SQLite, CRUD
│   ├── models.py            # Pydantic схемы
│   ├── proxy_parser.py      # Парсер ссылок (hex + base64)
│   ├── checks/
│   │   ├── tcp_tls_check.py     # TCP/TLS проверки
│   │   ├── fingerprint_check.py # TLS-отпечатки (scapy)
│   │   ├── server_info.py       # GeoIP через ip-api.com
│   │   ├── diagnostics.py       # Сертификат, стабильность, DPI, DNS
│   │   └── runner.py            # Очередь, оркестрация
│   ├── routers/
│   │   ├── api.py           # POST /api/check, GET /api/status
│   │   ├── admin.py         # Админ-панель API
│   │   └── ws.py            # WebSocket
│   └── client_hello/        # Бинарные ClientHello (Chrome, Firefox, Safari, curl)
├── static/                  # CSS, JS
├── templates/               # HTML (index, admin)
├── deploy/                  # nginx, systemd, deploy script
├── requirements.txt
└── .env.example
```

## Лицензия

MIT
