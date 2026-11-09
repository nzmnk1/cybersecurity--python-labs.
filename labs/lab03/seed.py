"""Початкове заповнення бази даними з data/seed.json."""

import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from labs.lab03.database import get_connection, initialize_database

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"
ALLOWED_STATUSES = {"new", "in_progress", "done"}
CATEGORY_KEYS = {"id", "name"}
RECORD_KEYS = {"code", "title", "category_id", "value", "status"}


class SeedError(Exception):
    """Початкові дані некоректні або їх не вдалося записати."""


def _is_int(value: object) -> bool:
    """Перевірити, що значення є цілим числом (bool не підходить)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_text(value: object, min_len: int, max_len: int) -> bool:
    """Перевірити рядок за довжиною після обрізання пробілів."""
    return isinstance(value, str) and min_len <= len(value.strip()) <= max_len


def load_seed(path: Path = SEED_PATH) -> dict:
    """Прочитати JSON з початковими даними."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SeedError(f"Файл {path.name} не знайдено.") from exc
    except json.JSONDecodeError as exc:
        raise SeedError(f"Некоректний JSON: {exc.msg}.") from exc
    if not isinstance(data, dict):
        raise SeedError("Корінь JSON має бути об'єктом.")
    return data


def validate_seed(data: dict) -> None:
    """Перевірити структуру та значення початкових даних."""
    categories = data.get("categories")
    records = data.get("records")
    if not isinstance(categories, list) or len(categories) != 3:
        raise SeedError("Потрібно рівно 3 категорії.")
    if not isinstance(records, list) or len(records) != 8:
        raise SeedError("Потрібно рівно 8 записів.")

    category_ids: set[int] = set()
    for item in categories:
        if not isinstance(item, dict) or set(item) != CATEGORY_KEYS:
            raise SeedError("Категорія має містити лише поля id та name.")
        if not _is_int(item["id"]) or item["id"] <= 0:
            raise SeedError("id категорії має бути додатним цілим.")
        if not _is_text(item["name"], 2, 40):
            raise SeedError("Назва категорії має містити 2-40 символів.")
        category_ids.add(item["id"])
    if len(category_ids) != len(categories):
        raise SeedError("id категорій мають бути унікальними.")

    for item in records:
        if not isinstance(item, dict) or set(item) != RECORD_KEYS:
            raise SeedError(
                "Запис має містити поля code, title, category_id, value, status."
            )
        if not _is_text(item["code"], 3, 40):
            raise SeedError("code має містити 3-40 символів.")
        if not _is_text(item["title"], 3, 120):
            raise SeedError("title має містити 3-120 символів.")
        if item["category_id"] not in category_ids:
            raise SeedError(f"Невідома категорія у записі {item['code']}.")
        if not _is_int(item["value"]) or item["value"] < 0:
            raise SeedError(f"value у записі {item['code']} має бути цілим >= 0.")
        if item["status"] not in ALLOWED_STATUSES:
            raise SeedError(f"Недозволений статус у записі {item['code']}.")


def _database_has_data(connection: sqlite3.Connection) -> bool:
    """Перевірити, чи містить база хоча б один рядок."""
    for table in ("categories", "records"):
        # Назви таблиць тут сталі, а не введені користувачем.
        row = connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
        if row is not None:
            return True
    return False


def seed_database() -> str:
    """Заповнити порожню базу початковими даними в одній транзакції."""
    data = load_seed()
    validate_seed(data)
    initialize_database()

    with closing(get_connection()) as connection:
        if _database_has_data(connection):
            return "База вже містить дані, заповнення пропущено."
        try:
            with connection:
                connection.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    [(c["id"], c["name"]) for c in data["categories"]],
                )
                connection.executemany(
                    "INSERT INTO records "
                    "(code, title, category_id, value, status) "
                    "VALUES (?, ?, ?, ?, ?)",
                    [
                        (
                            r["code"],
                            r["title"],
                            r["category_id"],
                            r["value"],
                            r["status"],
                        )
                        for r in data["records"]
                    ],
                )
        except sqlite3.Error as exc:
            raise SeedError(
                f"Не вдалося записати дані, зміни скасовано: {exc}"
            ) from exc
    return "Додано 3 категорії та 8 записів."


if __name__ == "__main__":
    try:
        print(seed_database())
    except SeedError as error:
        print(f"Помилка: {error}")
        sys.exit(1)
