# Nginx Upload Guard MVP

MVP защитного слоя перед legacy-монолитом, который нельзя менять.

Проблема: монолит обрабатывает PDF и может выполнить опасный JavaScript/eval внутри файла.  
Решение: поставить перед ним Nginx/OpenResty и проверять upload-запросы до того, как они попадут в приложение.

## Архитектура

```text
User
  ↓
Nginx / OpenResty
  ↓
Lua upload guard
  ↓
Scanner service
  ↓
ClamAV + PDF policy checks
  ↓
Legacy monolith
```

Обычные `GET`-запросы идут сразу в монолит.
`POST/PUT/PATCH` с body сначала отправляются в scanner.

## Что проверяем

Scanner делает несколько проверок:

ClamAV scan для известных malware-сигнатур;
 - raw scan по байтам файла;
 - проверку PDF через pikepdf;
 - блокировку активного PDF-контента:
    - `/JavaScript`
    - `/JS`
    - `/OpenAction`
    - `/AA`
    - `/Launch`
    - `/EmbeddedFile`
    - `/AcroForm`
    - `/XFA`
    - `eval(`
    - `Function(`
    - `app.launchURL`
    - `submitForm`

Если файл подозрительный — Nginx возвращает 403, монолит файл не получает.

Если scanner или ClamAV недоступны — upload блокируется.

## Запуск
```bash
docker compose up -d --build
```

Или:

```bash
make up
```

## Генерация тестовых PDF
```bash
make generate-pdfs
```

Будут созданы:

```text
samples/clean.pdf
samples/js_action.pdf
samples/eicar.pdf
```

## Тесты

Чистый PDF должен пройти:
```bash
make test-clean-pdf
```

PDF с JavaScript должен заблокироваться:
```bash
make test-js-pdf
```

EICAR test file должен заблокироваться:
```bash
make test-eicar-txt
```

EICAR внутри PDF проверяет raw scan:
```bash
make test-eicar-pdf
```

## Логи
```bash
make logs
```

Только Nginx:
```bash
make logs-nginx
```

Только scanner:
```bash
make logs-scanner
```

Только ClamAV:
```bash
make logs-clamav
```

## Важно

Это не полноценный CDR и не окончательное исправление уязвимости в монолите.

Это compensating control: защитный слой перед приложением, которое нельзя менять.

Для production лучше добавить:

```text
строгий allowlist MIME/type;
qpdf --check;
нормализацию PDF через qpdf;
удаление активных PDF-объектов;
CDR-подход: render pages → build new clean PDF;
метрики и алерты;
запрет прямого доступа к монолиту в обход Nginx.
```

Главное правило: монолит должен получать только проверенные upload-запросы.