import csv
from datetime import datetime
import functools
import hashlib
import json
import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 14
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)


class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль закороткий: довжина {len(password)}, "
            f"потрібно щонайменше {MIN_PASSWORD_LENGTH} символів."
        )

    data_to_hash = f"{password}{salt}".encode("utf-8")
    return hashlib.sha512(data_to_hash).hexdigest()


def log_event(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = kwargs.get("username") if "username" in kwargs else args[0]
        timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

        try:
            res = func(*args, **kwargs)
            status_str = "success" if res else "failure"
        except Exception:
            status_str = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": status_str,
                "timestamp": timestamp,
                "args": list(args),
                "kwargs": kwargs,
            }

            existing_logs = []
            if os.path.exists(LOG_PATH):
                try:
                    with open(LOG_PATH, "r", encoding="utf-8") as f:
                        existing_logs = json.load(f)
                except (json.JSONDecodeError, OSError):
                    existing_logs = []

            existing_logs.append(log_entry)

            with open(LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(existing_logs, f, indent=4, ensure_ascii=False)

        return res

    return wrapper


users_to_register = (
    ("admin_alpha", "SuperSecretPass2026!"),
    ("analyst_beta", "ThreatHuntingPro99#"),
    ("manager_gamma", "CorporateSecRule2026$"),
    ("auditor_delta", "AuditComplianceKey123*"),
    ("dev_engineer", "BackendPythonDev2026_"),
    ("soc_operator", "IncidentHandling911!"),
    ("forensic_lead", "EvidenceAnalystMaster!"),
    ("cloud_security", "AwsGcpAzureSecurity77&"),
    ("network_admin", "CiscoPacketTracerRoot!"),
    ("intern_student", "CyberSecurityPolytech1"),
)


def create_user(username: str, password: str) -> tuple[str, str]:
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)

    with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["username", "password_hash"])
        for username, password in users_list:
            u_name, u_hash = create_user(username, password)
            writer.writerow([u_name, u_hash])


def read_users_db() -> list[dict[str, str]]:
    with open(CSV_PATH, mode="r", encoding="utf-8") as csv_file:
        users_db = list(csv.DictReader(csv_file))

    print("\n--- База користувачів (users.csv) ---")
    print(f"| {'Логін':<18} | {'Хеш SHA-512 (перші 28 символів)...':<36} |")
    print("-" * 60)
    for u in users_db:
        short_hash = u["password_hash"][:28] + "..."
        print(f"| {u['username']:<18} | {short_hash:<36} |")
    print("-" * 60 + "\n")

    return users_db


@log_event
def login(username: str, password: str, users_db: list[dict[str, str]]) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми.")

    try:
        calculated_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False

    for user in users_db:
        if user["username"] == username:
            return user["password_hash"] == calculated_hash

    return False


def main() -> None:
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}"
    )
    print(f"Персональна сіль: '{PERSONAL_SALT}' | Алгоритм: SHA-512\n")

    try:
        print("[1] Створення динамічної папки data та запис users.csv...")
        create_users(users_to_register)

        print("[2] Зчитування users.csv...")
        users_db = read_users_db()

        print("[3] Демонстрація перехоплення винятків валідації:")
        try:
            generate_hash("short", PERSONAL_SALT)
        except ValidationError as err:
            print(f"   [Очікуваний виняток ValidationError]: {err}")

        print("\n[4] Тестування автентифікації та JSON-логування:")

        ok = login("admin_alpha", "SuperSecretPass2026!", users_db=users_db)
        print(f"   Спроба входу admin_alpha: {'УСПІШНО' if ok else 'ВІДХИЛЕНО'}")

        fail_pass = login(
            "admin_alpha", "WrongPasswordLength123!", users_db=users_db
        )
        print(
            f"   Спроба входу admin_alpha (невірний пароль): "
            f"{'УСПІШНО' if fail_pass else 'ВІДХИЛЕНО'}"
        )

        fail_user = login(
            "unknown_user", "AnyValidPassword123!", users_db=users_db
        )
        print(
            f"   Спроба входу unknown_user: "
            f"{'УСПІШНО' if fail_user else 'ВІДХИЛЕНО'}"
        )

        print(f"\n[5] Усі події зафіксовані у файлі: {LOG_PATH}")

    except (FileNotFoundError, PermissionError, OSError) as fs_err:
        print(f"Помилка файлової системи: {fs_err}")
    except (ValidationError, ValueError) as val_err:
        print(f"Помилка валідації даних: {val_err}")


if __name__ == "__main__":
    main()