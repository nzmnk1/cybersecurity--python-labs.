    # Лабораторна робота №2: консольні утиліти для задач кібербезпеки

**Варіант 4:** Парсер логів аутентифікації SSH / Linux Auth Log (виявлення брутфорсу в `auth.log`).

## Встановлення

Усі команди виконуються з кореня репозиторію в активованому віртуальному середовищі (`.venv` з ЛР №1).

```
pip install -r requirements.txt
```

У `requirements.txt` є `ruff`. Інших зовнішніх залежностей немає, використовується лише стандартна бібліотека.

## Структура файлів

```
labs/lab02/
├── __init__.py
├── main.py       # команди demo та analyze
├── task1.py      # User, Admin, Session, AuditLog, UserAccount
├── task2.py      # аналізатор SSH auth.log
├── README.md
└── data/
    └── data_v04/
        └── auth.log   # вхідний файл варіанта 4 з lab2_data.zip
```

Вхідний файл: `data/data_v04/auth.log`, журнал `sshd` у форматі syslog, 20 рядків. Приклад рядка:

```
Sep 27 14:00:00 server01 sshd[2750]: Failed password for admin from 203.0.113.77 port 53000 ssh2
```

Програма розпізнає рядки `Failed password` та `Accepted password` (зокрема `for invalid user <ім'я>`). Інші рядки пропускаються з попередженням.

## Запуск

Демонстрація Завдання 1 (ООП):

```
python -m labs.lab02.main demo
```

Аналіз журналу (Завдання 2). Без аргументів береться `data/data_v04/auth.log`:

```
python -m labs.lab02.main analyze
python -m labs.lab02.main analyze --auth-log labs/lab02/data/data_v04/auth.log --threshold 5 --window-min 5 --output-json labs/lab02/data/ssh_report.json
python -m labs.lab02.main analyze --threshold 3
python -m labs.lab02.main analyze --window-min 60 --threshold 4
```

## Параметри CLI (`analyze`)

| Параметр | Опис | За замовчуванням |
|---|---|---|
| `--auth-log` | шлях до `auth.log` | `labs/lab02/data/data_v04/auth.log` |
| `--threshold` | тривога, якщо невдалих спроб **більше** за це число | `5` |
| `--window-min` | довжина часового вікна в хвилинах | `5` |
| `--output-json` | шлях до JSON-звіту (каталог створюється автоматично) | не записується |
| `--year` | рік для міток часу (в `auth.log` його немає) | поточний рік |

`--threshold`, `--window-min` і `--year` мають бути цілими числами більше нуля, інакше `argparse` завершить роботу з повідомленням про помилку.

## Як працює аналіз

1. Файл читається порядково генератором, регулярний вираз `re` витягує час, користувача, IP та результат (`Failed` / `Accepted`).
2. Невдалі спроби групуються за IP у `collections.defaultdict`.
3. Для кожного IP пошук найбільшої кількості невдач у будь-якому вікні `--window-min` хвилин. Якщо вона більша за `--threshold`, IP вважається джерелом брутфорсу.
4. Якщо після невдач з цього IP був успішний вхід, виводиться окреме попередження про можливу компрометацію.
5. Знайдені IP потрапляють у список на блокування. Тривоги записуються через `logging.error`.

## Поведінка при помилках

- Файлу немає: `[ERROR] Log file not found: ...`, код завершення 1.
- Немає прав на читання або інша помилка вводу-виводу: повідомлення в лог, код завершення 1.
- Рядок не схожий на подію SSH: пропускається, у кінці виводиться кількість пропущених.
- Не вдалося записати звіт: повідомлення в лог, код завершення 1.
- Некоректні числові аргументи: помилка `argparse`.
- Некоректні дані в `auth.log` (невалідні байти) не зупиняють програму.

## Приклад результату на `data_v04/auth.log`

```
[INFO] Analyzing authentication events in labs\lab02\data\data_v04\auth.log...
[INFO] Processed 20 lines (Time range: 2026-09-27 08:10:00 - 2026-09-27 18:32:00)

=== SSH Bruteforce Detection Results ===
Failed Attempts Threshold: >5 attempts in 5 minutes
[ERROR] Bruteforce Detected! IP: 203.0.113.77 | Total Failures: 7 | Target Users: admin
[ERROR] IP 203.0.113.77 later logged in successfully: account may be compromised!

=== Recommended Blocklist (IPs) ===
203.0.113.77
```

Пояснення знайдених аномалій:

- `203.0.113.77`: 7 невдалих входів для `admin` за 3,5 хвилини, потім успішний вхід о 14:05. Підбір пароля, імовірно, вдався.
- `198.51.100.88`: 5 невдалих спроб для неіснуючого користувача `test` протягом 48 хвилин. Повільна атака, у вікно 5 хвилин не потрапляє (видно з `--window-min 60 --threshold 4`).
- `192.0.2.55`: 4 невдалі спроби для `root` за 2 хвилини. Нижче порога за замовчуванням, але видно з `--threshold 3`.

## Перевірка якості коду

```
ruff check .
ruff format --check .
```