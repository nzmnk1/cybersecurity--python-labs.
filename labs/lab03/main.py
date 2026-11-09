"""FastAPI-застосунок: облік подій автентифікації (варіант 4)."""

import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from labs.lab03 import config, repository
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logger = logging.getLogger(__name__)

DESCRIPTION = (
    "Сервіс зберігає підсумки спостережень за автентифікацією. "
    "Один запис описує кількість подій певного типу за навчальний інтервал. "
    f"Одиниця вимірювання: {config.UNIT} (цілі числа, не менше 0). "
    f"Поріг: {config.THRESHOLD} подій. Усі дані навчальні."
)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску; дані не змінюються."""
    initialize_database()
    yield


app = FastAPI(
    title="Облік подій автентифікації",
    description=DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(repository.NotFoundError)
def handle_not_found(_request: Request, error: repository.NotFoundError):
    """Перетворити NotFoundError на 404."""
    return JSONResponse(status_code=404, content={"detail": str(error)})


@app.exception_handler(repository.ConflictError)
def handle_conflict(_request: Request, error: repository.ConflictError):
    """Перетворити ConflictError на 409."""
    return JSONResponse(status_code=409, content={"detail": str(error)})


@app.exception_handler(sqlite3.Error)
def handle_sqlite_error(_request: Request, error: sqlite3.Error):
    """Записати технічну помилку в лог, клієнту дати загальне повідомлення."""
    logger.exception("Помилка SQLite: %s", error)
    return JSONResponse(
        status_code=500, content={"detail": "Внутрішня помилка сервера."}
    )


@app.get("/ping", summary="Перевірка доступності API", tags=["service"])
def ping() -> dict[str, str]:
    """Повернути статус доступності API."""
    return {"status": "ok"}


@app.get("/student", summary="Дані студента", tags=["service"])
def student() -> dict[str, str | int]:
    """Повернути ПІБ, групу та номер варіанта з shared/student.py."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
