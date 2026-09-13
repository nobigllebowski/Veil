# Veil — сквозное шифрование на .NET 10

Veil — мессенджер в духе Signal: сервер на ASP.NET Core 10, real-time через SignalR, собственная реализация
протокола **PQXDH** (X25519 + постквантовый **ML-KEM-768**) и **Double Ratchet** на C#, клиентский SDK,
**веб-клиент на Blazor WebAssembly**, который раздаёт сам API, и терминальный клиент. Текст сообщения
шифруется на устройстве отправителя и расшифровывается только на устройствах получателя; сервер хранит и
маршрутизирует шифротекст и удаляет его после подтверждения доставки.

## Что внутри

- **Криптография** (`Veil.Crypto`, чистая библиотека без зависимостей от сервера): PQXDH-рукопожатие с
  гибридом X25519 + ML-KEM-768, Double Ratchet с AES-256-GCM, подписи Ed25519 с доменным разделением,
  паддинг длины, safety numbers для проверки ключей, экспорт/импорт состояния сессий. Тесты включают
  контрольные векторы RFC 7748 / 8032 / 5869 / 4231 и GCM.
- **Безопасность сервера**: Argon2id-хеши паролей (PHC-формат, прозрачный ре-хеш), выравнивание времени
  ответа при неизвестном пользователе, блокировка после серии неудач, ES256-токены на 10 минут, refresh-токены
  с ротацией и детекцией повторного использования (повтор аннулирует всю семью), security stamp и проверка
  отзыва устройства на каждом запросе, TOTP с защитой от replay, шифрование колонок (e-mail, TOTP-секрет,
  название группы) с blind-индексом, хеш-цепочка аудита с advisory-lock, rate limiting по слоям, строгие
  заголовки безопасности, RFC 9457 problem details.
- **Веб-клиент** (`Veil.Web`): полноценный мессенджер в браузере — регистрация и вход (с TOTP), список
  чатов с непрочитанными и статусом «online», переписка с галочками доставки и индикатором набора, личные и
  групповые чаты, участники, проверка safety number, устройства и подключение TOTP по QR-коду. Криптография
  (`Veil.Crypto` и `Veil.Client.Sdk`) выполняется прямо в браузере в WebAssembly; ключи устройства, сессии
  и история лежат в `localStorage`, зашифрованные AES-256-GCM ключом из пароля (Argon2id), который хранится
  только в `sessionStorage`. Клиент отдаётся с того же origin, что и API, под строгим CSP.
- **Multi-device**: сервер отклоняет отправку, если пропущено хотя бы одно активное устройство получателя,
  и возвращает точную разницу; одноразовые pre-key выдаются атомарно (`DELETE … RETURNING … SKIP LOCKED`).
- **Архитектура**: Clean Architecture + vertical slices, свой CQRS-диспетчер с пайплайном валидации и
  логирования, DDD-агрегаты с доменными событиями, transactional outbox, EF Core 10 + PostgreSQL 17, Redis 7,
  HybridCache, OpenTelemetry, Serilog, .NET Aspire, Scalar, центральное управление версиями пакетов,
  анализаторы в режиме warnings-as-errors.
- **Тесты**: 159 тестов — криптография, домен, обработчики, инфраструктура, архитектурные правила
  (NetArchTest), интеграционные end-to-end сценарии на реальных PostgreSQL/Redis и браузерный сценарий на
  Playwright, который прогоняет настоящий веб-клиент в Chromium.
- **Поставка**: chiseled-контейнер без root и без shell, Compose со стеком и Caddy TLS, CI на GitHub Actions
  (форматирование, анализаторы, тесты, Trivy, CodeQL, dependency review).

## Быстрый старт

```bash
# вариант 1: Aspire (нужен Docker)
dotnet run --project src/Veil.AppHost

# вариант 2: сервисы в Docker, API из CLI
docker compose -f docker-compose.dev.yml up -d
dotnet run --project src/Veil.Api

# вариант 3: свой локальный PostgreSQL — один раз создать роль и базы
psql -U postgres -f scripts/init-local-postgres.sql
# либо задать свои учётные данные через user secrets в src/Veil.Api:
#   dotnet user-secrets set "ConnectionStrings:Postgres" "Host=localhost;Port=5432;Database=veil;Username=postgres;Password=<пароль>"
# Redis для разработки не обязателен: при пустом ConnectionStrings:Redis API работает в
# режиме одного экземпляра (presence, защита TOTP от replay и кэш в памяти, без SignalR backplane).

# два терминала для чата (альтернатива браузеру)
dotnet run --project src/Veil.Client -- --server https://localhost:7443 --insecure
```

После запуска API откройте **https://localhost:7443** — это и есть мессенджер. Создайте аккаунт, затем в
приватном окне (или другом браузере) второй, и начните чат по имени пользователя. Сообщения, галочки
доставки, набор текста и статус «online» обновляются в реальном времени; замок в шапке чата показывает
safety number для сверки. В настройках (аватар слева сверху) — TOTP, устройства и выход с очисткой или
сохранением локального зашифрованного состояния.

Команды клиента: `/chat <user>`, `/group <title> <user>…`, `/list`, `/open <#>`, `/devices`, `/safety`,
`/totp`, `/logout`. Локальное состояние (ключи устройства, сессии) хранится в `~/.veil/` в файле,
зашифрованном AES-256-GCM под ключом из парольной фразы (Argon2id).

## Тесты

```bash
dotnet test --solution Veil.slnx
```

Интеграционные тесты поднимают PostgreSQL и Redis через Testcontainers; без Docker укажите готовые сервисы
переменными `VEIL_TEST_POSTGRES` и `VEIL_TEST_REDIS`. Браузерный тест (`tests/Veil.Web.E2ETests`) запускает
собранный API на свободном порту (база `veil_e2e`, переменная `VEIL_E2E_POSTGRES`) и управляет Chromium
через Playwright: один раз установите браузер
(`pwsh tests/Veil.Web.E2ETests/bin/Debug/net10.0/playwright.ps1 install chromium` или
`npx playwright install chromium`) либо укажите путь к своему в `VEIL_E2E_CHROMIUM`.

Подробнее: [README.md](README.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
