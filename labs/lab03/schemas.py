"""Pydantic-моделі запитів і відповідей (варіант 4: кількість подій)."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    """Тіло запиту для створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Категорія у відповіді API."""

    id: int


class RecordCreate(BaseModel):
    """Тіло запиту для створення запису."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: int = Field(ge=0, strict=True)
    status: Status


class RecordReplace(RecordCreate):
    """Тіло запиту для повної заміни запису (усі поля обов'язкові)."""


class RecordRead(RecordCreate):
    """Запис у відповіді API."""

    id: int
    category_name: str
