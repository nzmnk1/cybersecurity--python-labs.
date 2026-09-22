"""Завдання 3: Хешування, CSV-база та JSON-логування з винятками."""

import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import STUDENT_NAME, VARIANT_NUMBER

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
CSV_FILE_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_FILE_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 14
HASH_SALT = str(VARIANT_NUMBER).zfill(5)


class ValidationError(Exception):
    """Власний виняток для валідації довжини пароля."""



def log_event(func):
    """Декоратор для фіксації подій у JSON-журналі."""

    @functools.wraps(func)
    def wrapper(username: str, password: str, *args, **kwargs):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        is_success = False
        try:
            result = func(username, password, *args, **kwargs)
            is_success = bool(result)
            return result
        finally:
            log_record = {
                "event": "login",
                "user": username,
                "result": "success" if is_success else "failure",
                "timestamp": timestamp,
                "args": [username, "***"],
                "kwargs": kwargs,
            }
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                history = []
                if os.path.exists(LOG_FILE_PATH):
                    with open(LOG_FILE_PATH, "r", encoding="utf-8") as file:
                        try:
                            history = json.load(file)
                        except json.JSONDecodeError:
                            history = []
                history.append(log_record)
                with open(LOG_FILE_PATH, "w", encoding="utf-8") as file:
                    json.dump(history, file, indent=4, ensure_ascii=False)
            except (OSError, PermissionError) as exc:
                print(f"[Помилка логування]: {exc}")

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує хеш SHA-512 від конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль занадто короткий. Мінімум {MIN_PASSWORD_LENGTH} символів."
        )

    salted_string = (password + salt).encode("utf-8")
    return hashlib.sha512(salted_string).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Створює запис користувача з персональною сіллю."""
    return username, generate_hash(password, HASH_SALT)


def create_users(users_list: tuple[tuple[str, str], ...]) -> bool:
    """Записує список користувачів у файл data/users.csv з відловом винятків."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CSV_FILE_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash"])
            for username, raw_password in users_list:
                _, pwd_hash = create_user(username, raw_password)
                writer.writerow([username, pwd_hash])
        return True
    except (ValidationError, ValueError) as val_err:
        print(f"[Помилка валідації при створенні бази]: {val_err}")
    except (OSError, PermissionError) as file_err:
        print(f"[Помилка запису файлу бази]: {file_err}")
    return False


def read_users_db() -> list[dict[str, str]]:
    """Зчитує базу користувачів із CSV-файлу з відловом винятків."""
    users_db: list[dict[str, str]] = []
    try:
        if not os.path.exists(CSV_FILE_PATH):
            raise FileNotFoundError(f"Файл бази даних {CSV_FILE_PATH} не знайдено.")
        with open(CSV_FILE_PATH, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            users_db = list(reader)
    except (FileNotFoundError, PermissionError, OSError) as fs_err:
        print(f"[Помилка файлової системи]: {fs_err}")
    return users_db


@log_event
def login(username: str, password: str, users_db: list[dict[str, str]]) -> bool:
    """Перевірка автентифікації з відловом помилок валідації всередині функції."""
    try:
        if not username or not password:
            raise ValueError("Логін та пароль не можуть бути порожніми.")

        user_record = next(
            (u for u in users_db if u.get("username") == username), None
        )
        if not user_record:
            return False

        calculated_hash = generate_hash(password, HASH_SALT)
        return user_record.get("password_hash") == calculated_hash
    except (ValidationError, ValueError) as val_err:
        print(f"[Помилка валідації під час автентифікації]: {val_err}")
        return False


def print_users_db(users_db: list[dict[str, str]]) -> None:
    """Вивід таблиці користувачів."""
    w_num = 4
    w_user = 18
    w_hash = 36

    header = (
        f"| {'№':<{w_num}} "
        f"| {'Користувач':<{w_user}} "
        f"| {'Хеш SHA-512 (обрізано)':<{w_hash}} |"
    )
    separator = "-" * len(header)

    print(
        f"\nБаза даних користувачів (Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER})"
    )
    print(separator)
    print(header)
    print(separator)

    for idx, row in enumerate(users_db, start=1):
        u_name = row.get("username", "")
        u_hash = row.get("password_hash", "")
        display_hash = (
            f"{u_hash[:32]}..." if len(u_hash) > 35 else u_hash
        )
        print(
            f"| {idx:<{w_num}} "
            f"| {u_name:<{w_user}} "
            f"| {display_hash:<{w_hash}} |"
        )
    print(separator + "\n")


def main() -> None:
    users_data = (
        ("ciso_office", "SuperSecur3Key!2026"),
        ("threat_hunter", "Tr4ckThreats#Master"),
        ("junior_dev", "C0d1ngSecur1ty!Dev"),
        ("visitor_acc", "V1s1t0rAccess#9999"),
        ("legacy_sys", "0ldLegacyP@ssword!"),
        ("soc_analyst", "SOCMonitoring#Pass1"),
        ("forensic_eng", "F0rens1cExpert@2026"),
        ("audit_lead", "Aud1tCompl1ance!Max"),
        ("network_admin", "R0ut3rSw1tch#Strong"),
        ("intern_student", "Learn1ngCyb3r#Pass"),
    )

    print("[*] Створення бази користувачів:")
    if create_users(users_data):
        print("[+] Базу користувачів успішно записано.")

    db = read_users_db()
    if db:
        print_users_db(db)

    print("[*] Тестування автентифікації:")
    res_ok = login("ciso_office", "SuperSecur3Key!2026", db)
    print(f" -> ciso_office (вірний пароль): {res_ok}")

    res_fail = login("ciso_office", "WrongPassword!2026", db)
    print(f" -> ciso_office (невірний пароль): {res_fail}")

    print("\n[*] Тестування відлову некоректних даних:")
    res_short = login("ciso_office", "short1!", db)
    print(f" -> Результат для короткого пароля: {res_short}")

    res_empty = login("", "SuperSecur3Key!2026", db)
    print(f" -> Результат для порожнього логіна: {res_empty}")


if __name__ == "__main__":
    main()