"""Параметризовані SQL-запити до таблиць categories і records."""

import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection

RECORD_SELECT = (
    "SELECT r.id, r.code, r.title, r.category_id, "
    "c.name AS category_name, r.value, r.status "
    "FROM records AS r JOIN categories AS c ON c.id = r.category_id"
)


class RepositoryError(Exception):
    """Базова помилка шару доступу до даних."""


class NotFoundError(RepositoryError):
    """Запис або категорія не існує."""


class ConflictError(RepositoryError):
    """Дублікат унікального значення або категорія містить записи."""


def _connect() -> sqlite3.Connection:
    """Відкрити з'єднання, яке повертає рядки як sqlite3.Row."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def _is_unique_violation(error: sqlite3.IntegrityError) -> bool:
    """Перевірити, що порушено обмеження UNIQUE."""
    return "UNIQUE constraint failed" in str(error)


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    """Перевірити існування категорії."""
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    return row is not None


def _get_record(connection: sqlite3.Connection, record_id: int) -> dict[str, Any]:
    """Прочитати запис разом із назвою категорії або викликати NotFoundError."""
    row = connection.execute(RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    if row is None:
        raise NotFoundError("Запис не знайдено.")
    return dict(row)


# --- Категорії ---


def list_categories() -> list[dict[str, Any]]:
    """Повернути всі категорії за зростанням id."""
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id ASC"
        ).fetchall()
    return [dict(row) for row in rows]


def create_category(name: str) -> dict[str, Any]:
    """Створити категорію; дубль назви дає ConflictError."""
    with closing(_connect()) as connection:
        try:
            with connection:
                cursor = connection.execute(
                    "INSERT INTO categories (name) VALUES (?)", (name,)
                )
        except sqlite3.IntegrityError as error:
            if _is_unique_violation(error):
                raise ConflictError("Категорія з такою назвою вже існує.") from error
            raise
    return {"id": cursor.lastrowid, "name": name}


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with closing(_connect()) as connection:
        try:
            with connection:
                if not _category_exists(connection, category_id):
                    raise NotFoundError("Категорію не знайдено.")
                connection.execute(
                    "DELETE FROM categories WHERE id = ?", (category_id,)
                )
        except sqlite3.IntegrityError as error:
            if "FOREIGN KEY" in str(error):
                raise ConflictError("Категорія містить записи.") from error
            raise


# --- Записи ---


def create_record(
    code: str, title: str, category_id: int, value: int, status: str
) -> dict[str, Any]:
    """Додати запис і повернути його разом із category_name."""
    with closing(_connect()) as connection:
        try:
            with connection:
                if not _category_exists(connection, category_id):
                    raise NotFoundError("Категорію не знайдено.")
                cursor = connection.execute(
                    "INSERT INTO records (code, title, category_id, value, status) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (code, title, category_id, value, status),
                )
                return _get_record(connection, cursor.lastrowid)
        except sqlite3.IntegrityError as error:
            if _is_unique_violation(error):
                raise ConflictError("Запис із таким code вже існує.") from error
            raise


def get_record(record_id: int) -> dict[str, Any]:
    """Отримати один запис за id."""
    with closing(_connect()) as connection:
        return _get_record(connection, record_id)


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: int | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Повернути записи з фільтрами (AND) і поділом на сторінки."""
    conditions: list[str] = []
    params: list[Any] = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)

    sql = RECORD_SELECT
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(_connect()) as connection:
        rows = connection.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def update_record(
    record_id: int,
    code: str,
    title: str,
    category_id: int,
    value: int,
    status: str,
) -> dict[str, Any]:
    """Повністю замінити змінювані поля запису; id не змінюється."""
    with closing(_connect()) as connection:
        try:
            with connection:
                _get_record(connection, record_id)
                if not _category_exists(connection, category_id):
                    raise NotFoundError("Категорію не знайдено.")
                connection.execute(
                    "UPDATE records SET code = ?, title = ?, category_id = ?, "
                    "value = ?, status = ? WHERE id = ?",
                    (code, title, category_id, value, status, record_id),
                )
                return _get_record(connection, record_id)
        except sqlite3.IntegrityError as error:
            if _is_unique_violation(error):
                raise ConflictError("Запис із таким code вже існує.") from error
            raise


def delete_record(record_id: int) -> None:
    """Видалити запис за id."""
    with closing(_connect()) as connection, connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено.")


def create_records_bulk(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Атомарно додати пакет записів в одній транзакції."""
    with closing(_connect()) as connection:
        try:
            with connection:
                category_ids = sorted({item["category_id"] for item in items})
                # Підставляються лише символи "?", значення йдуть параметрами.
                placeholders = ",".join("?" * len(category_ids))
                existing = {
                    row["id"]
                    for row in connection.execute(
                        f"SELECT id FROM categories WHERE id IN ({placeholders})",
                        category_ids,
                    )
                }
                if existing != set(category_ids):
                    raise NotFoundError("Категорію не знайдено.")

                new_ids: list[int] = []
                for item in items:
                    cursor = connection.execute(
                        "INSERT INTO records "
                        "(code, title, category_id, value, status) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (
                            item["code"],
                            item["title"],
                            item["category_id"],
                            item["value"],
                            item["status"],
                        ),
                    )
                    new_ids.append(cursor.lastrowid)
                return [_get_record(connection, new_id) for new_id in new_ids]
        except sqlite3.IntegrityError as error:
            if _is_unique_violation(error):
                raise ConflictError("Дублікат code у базі або в пакеті.") from error
            raise
