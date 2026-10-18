"""Завдання 1: модель користувача, безпечних сеансів та журналу аудиту."""

import hashlib
import hmac
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS = 600_000
SALT_SIZE_BYTES = 16
SESSION_TIMEOUT_SEC = 900

EMAIL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")

ACTION_LOGIN_SUCCESS = "login_success"
ACTION_LOGIN_FAILURE = "login_failure"
ACTION_LOGOUT = "logout"
ALLOWED_ACTIONS = frozenset({ACTION_LOGIN_SUCCESS, ACTION_LOGIN_FAILURE, ACTION_LOGOUT})


def utc_now() -> datetime:
    """Поточний час UTC з часовим поясом (без неоднозначності локального часу)."""
    return datetime.now(timezone.utc)


class User:
    """Користувач із безпечним зберіганням пароля (PBKDF2 + сіль)."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "user",
        active: bool = True,
    ) -> None:
        if not username:
            raise ValueError("Ім'я користувача не може бути порожнім")
        self.username = username
        self.email = email  # проходить через setter з перевіркою
        self.role = role
        self.active = active
        # Подвійне підкреслення: Python перейменує атрибути (name mangling)
        # на _User__password_hash / _User__password_salt.
        self.__password_hash = b""
        self.__password_salt = b""
        self.set_password(password)

    @property
    def email(self) -> str:
        """Електронна адреса користувача."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or EMAIL_RE.fullmatch(value) is None:
            raise ValueError(f"Невалідний email: {value!r}")
        self._email = value

    @staticmethod
    def _derive_hash(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def set_password(self, password: str) -> None:
        """Згенерувати нову сіль і зберегти хеш пароля (сам пароль не зберігається)."""
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль має бути непорожнім рядком")
        self.__password_salt = os.urandom(SALT_SIZE_BYTES)
        self.__password_hash = self._derive_hash(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        """Перевірити пароль порівнянням у постійному часі."""
        if not isinstance(password, str) or not password:
            return False
        candidate = self._derive_hash(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        """Вимкнути обліковий запис."""
        self.active = False

    def __str__(self) -> str:
        return (
            f"{type(self).__name__}(username={self.username!r}, "
            f"email={self.email!r}, role={self.role!r}, active={self.active})"
        )


class Admin(User):
    """Адміністратор: користувач з набором дозволів (наслідування)."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        permissions: Iterable[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, password, role="admin", active=active)
        # Нова множина для кожного об'єкта, не змінюваний типовий аргумент.
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        """Додати дозвіл."""
        if not permission:
            raise ValueError("Дозвіл не може бути порожнім")
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Забрати дозвіл (якщо його не було, нічого не відбувається)."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Чи є в адміністратора такий дозвіл."""
        return permission in self.permissions

    def __str__(self) -> str:
        shown = ", ".join(sorted(self.permissions)) or "-"
        return f"{super().__str__()} permissions=[{shown}]"


class Session:
    """Сеанс користувача; усі мітки часу в UTC."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.login_time = utc_now()
        self.last_activity = self.login_time

    def touch(self) -> None:
        """Оновити час останньої активності."""
        self.last_activity = utc_now()

    def is_active(self, timeout_sec: int) -> bool:
        """Чи не минув таймаут з моменту останньої активності."""
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        idle = utc_now() - self.last_activity
        return idle <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditEntry:
    """Запис журналу аудиту; __init__, __repr__ та __eq__ генерує @dataclass."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій автентифікації (паролі сюди не потрапляють)."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        """Додати запис про дію користувача."""
        if action not in ALLOWED_ACTIONS:
            raise ValueError(f"Невідома дія: {action!r}")
        self.entries.append(AuditEntry(utc_now(), username, action))

    def show_all(self) -> None:
        """Вивести всі записи журналу."""
        if not self.entries:
            print("(журнал порожній)")
        for entry in self.entries:
            stamp = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")
            print(f"{stamp} | {entry.username:<12} | {entry.action}")


# Дозволені ключі UserAccount["..."] та типи їхніх значень.
_ACCOUNT_FIELDS: dict[str, type | tuple[type, ...]] = {
    "user": User,
    "session": (Session, type(None)),
    "audit_log": AuditLog,
}


class UserAccount:
    """Обліковий запис: композиція User + Session + AuditLog."""

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Автентифікація; сеанс створюється лише після успішної перевірки."""
        success = (
            username == self.user.username
            and self.user.active
            and self.user.check_password(password)
        )
        if not success:
            self.audit_log.add_log(username, ACTION_LOGIN_FAILURE)
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, ACTION_LOGIN_SUCCESS)
        return True

    def is_authenticated(self) -> bool:
        """Чи є сеанс і чи не минув його термін (перевірка його не подовжує)."""
        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> bool:
        """Завершити сеанс і записати подію; False, якщо сеансу не було."""
        if self.session is None:
            return False
        self.session = None
        self.audit_log.add_log(self.user.username, ACTION_LOGOUT)
        return True

    def __getitem__(self, key: str) -> object:
        if key not in _ACCOUNT_FIELDS:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: object) -> None:
        if key not in _ACCOUNT_FIELDS:
            raise KeyError(key)
        if not isinstance(value, _ACCOUNT_FIELDS[key]):
            got = type(value).__name__
            raise TypeError(f"Невірний тип значення для {key!r}: {got}")
        setattr(self, key, value)


def _section(title: str) -> None:
    print(f"\n=== {title} ===")


def demo() -> None:
    """Демонстрація роботи класів (запускається командою demo)."""
    audit = AuditLog()
    user = User("alice", "alice_01@example.com", "S3cure!Pass")
    account = UserAccount(user, audit_log=audit)

    _section("Користувач (пароль не показується)")
    print(user)

    _section("Вхід")
    print("Невірний пароль :", account.login("alice", "wrong-pass", "192.0.2.10"))
    print("Автентифікований:", account.is_authenticated())
    print("Вірний пароль   :", account.login("alice", "S3cure!Pass", "192.0.2.10"))
    print("Автентифікований:", account.is_authenticated())

    _section("Зміна email з валідацією")
    user.email = "alice_new@example.org"
    print("Новий email:", user.email)
    for bad in ("1alice@example.com", "al@example.com", "alice@localhost"):
        try:
            user.email = bad
        except ValueError as error:
            print("Відхилено:", error)

    _section("Доступ через account[...]")
    print("account['user'] ->", account["user"])
    for key in ("password_hash", "__password_salt"):
        try:
            account[key]
        except KeyError:
            print(f"account[{key!r}] -> KeyError (недозволений ключ)")
    try:
        account["user"] = "не користувач"
    except TypeError as error:
        print("TypeError:", error)

    _section("Адміністратор і права")
    admin = Admin("root_admin", "root_admin@example.com", "Adm1n!Pass")
    admin.grant_permission("read_logs")
    admin.grant_permission("manage_users")
    admin.revoke_permission("read_logs")
    print(admin)
    print("manage_users:", admin.has_permission("manage_users"))
    print("read_logs   :", admin.has_permission("read_logs"))

    _section("Завершення сеансу за таймаутом")
    assert account.session is not None
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print("Автентифікований після простою:", account.is_authenticated())
    try:
        account.session.is_active(0)
    except ValueError as error:
        print("is_active(0):", error)

    _section("Вихід із системи")
    print("Новий вхід:", account.login("alice", "S3cure!Pass", "192.0.2.10"))
    print("Вихід     :", account.logout())
    print("Автентифікований:", account.is_authenticated())

    _section("Журнал AuditLog")
    audit.show_all()
