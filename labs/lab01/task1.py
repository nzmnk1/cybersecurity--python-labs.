import os
import random
import string
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "password123",
    "Qwerty!2023",
    "admin",
    "MyP@ssword",
    "123456",
    "SecurePass!",
    "test",
    "P@ssword123",
    "welcome",
    "StrongP@ss1",
]
criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {
    "password",
    "123456",
    "admin",
    "test",
    "welcome",
    "qwerty",
}
indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
for idx in indices:
    passwords.append(passwords[idx])


def evaluate_password_strength(
    password: str,
    rules: dict,
    forbidden: set,
    all_passwords: list,
) -> str:
    min_length = rules.get("min_length", 8)
    if password in forbidden or len(password) < min_length:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in string.punctuation for char in password)

    all_met = has_digit and has_upper and has_lower and has_special
    is_unique = all_passwords.count(password) == 1

    if all_met and len(password) >= min_length + 4 and is_unique:
        return "Дуже сильний"
    if all_met and len(password) < min_length + 4:
        return "Сильний"
    if len(password) >= min_length and (
        has_digit or has_upper or has_lower or has_special
    ):
        return "Середній"
    return "Слабкий"


def print_password_report(results: list, all_passwords: list) -> None:
    w_idx = 4
    w_pwd = 24
    w_len = 9
    w_count = 14
    w_status = 16

    header = (
        f"| {'№':<{w_idx}} "
        f"| {'Пароль':<{w_pwd}} "
        f"| {'Довжина':<{w_len}} "
        f"| {'Входження':<{w_count}} "
        f"| {'Категорія':<{w_status}} |"
    )
    separator = "-" * len(header)

    print(
        f"\nЗвіт перевірки паролів (Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER})"
    )
    print(separator)
    print(header)
    print(separator)

    for idx, (pwd, status) in enumerate(results, start=1):
        count = all_passwords.count(pwd)
        count_str = f"{count} (дублікат)" if count > 1 else str(count)
        print(
            f"| {idx:<{w_idx}} "
            f"| {pwd:<{w_pwd}} "
            f"| {len(pwd):<{w_len}} "
            f"| {count_str:<{w_count}} "
            f"| {status:<{w_status}} |"
        )
    print(separator + "\n")


analysis_results = []
for pwd in passwords:
    stat = evaluate_password_strength(pwd, criteria, forbidden_passwords, passwords)
    analysis_results.append((pwd, stat))
print_password_report(analysis_results, passwords)
