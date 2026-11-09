"""Маршрути записів."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace, Status

router = APIRouter(prefix="/records", tags=["records"])

NOT_FOUND = {404: {"description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"description": "Запис із таким code вже існує"}}

RecordId = Annotated[int, Path(gt=0, description="Ідентифікатор запису")]


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список записів із фільтрами",
)
def list_records(
    category_id: Annotated[
        int | None, Query(gt=0, description="Лише записи цієї категорії")
    ] = None,
    status: Annotated[
        Status | None, Query(description="Лише записи з цим статусом")
    ] = None,
    min_value: Annotated[
        int | None, Query(ge=0, description="Мінімальна кількість подій")
    ] = None,
    q: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=120,
            description="Буквальний підрядок у title (з урахуванням регістру)",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Максимум записів")] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,
) -> list[dict]:
    """Повернути записи з фільтрами, об'єднаними через AND, відсортовані за id."""
    return repository.list_records(
        category_id=category_id,
        status=status,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=201,
    summary="Пакетне створення записів",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    payload: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    """Атомарно створити від 1 до 100 записів в одній транзакції."""
    return repository.create_records_bulk([item.model_dump() for item in payload])


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис",
    responses={404: NOT_FOUND[404]},
)
def get_record(record_id: RecordId) -> dict:
    """Повернути один запис за id."""
    return repository.get_record(record_id)


@router.post(
    "",
    response_model=RecordRead,
    status_code=201,
    summary="Створити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(payload: RecordCreate) -> dict:
    """Створити запис; id визначає база."""
    return repository.create_record(**payload.model_dump())


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, payload: RecordReplace) -> dict:
    """Замінити всі змінювані поля запису; id лишається незмінним."""
    return repository.update_record(record_id, **payload.model_dump())


@router.delete(
    "/{record_id}",
    status_code=204,
    summary="Видалити запис",
    responses={404: NOT_FOUND[404]},
)
def delete_record(record_id: RecordId) -> None:
    """Видалити запис за id."""
    repository.delete_record(record_id)
