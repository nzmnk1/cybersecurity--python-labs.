"""Маршрути категорій."""

from fastapi import APIRouter, Path

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Список категорій",
)
def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=201,
    summary="Створити категорію",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category(payload: CategoryCreate) -> dict:
    """Створити нову категорію."""
    return repository.create_category(payload.name)


@router.delete(
    "/{category_id}",
    status_code=204,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def delete_category(
    category_id: int = Path(gt=0, description="Ідентифікатор категорії"),
) -> None:
    """Видалити категорію, якщо в ній немає записів."""
    repository.delete_category(category_id)
