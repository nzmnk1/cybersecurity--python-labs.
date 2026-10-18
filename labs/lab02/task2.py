"""Завдання 2 (варіант 4): аналізатор SSH auth.log та виявлення брутфорсу."""

import argparse
import json
import logging
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_LOG = Path(__file__).parent / "data" / "data_v04" / "auth.log"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MIN = 5

MONTHS = {
    name: number
    for number, name in enumerate(
        [
            "Jan",
            "Feb",
            "Mar",
            "Apr",
            "May",
            "Jun",
            "Jul",
            "Aug",
            "Sep",
            "Oct",
            "Nov",
            "Dec",
        ],
        start=1,
    )
}

AUTH_RE = re.compile(
    r"""
    ^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+
    (?P<time>\d{2}:\d{2}:\d{2})\s+
    (?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+
    (?P<result>Failed|Accepted)\s+password\s+for\s+
    (?P<invalid>invalid\s+user\s+)?
    (?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class AuthEvent:
    """Одна подія входу через SSH."""

    timestamp: datetime
    host: str
    user: str
    ip: str
    success: bool
    invalid_user: bool


@dataclass
class ParseStats:
    """Лічильники рядків під час читання файлу."""

    total_lines: int = 0
    skipped_lines: int = 0


@dataclass
class BruteforceFinding:
    """IP-адреса, яка перевищила поріг невдалих спроб у часовому вікні."""

    ip: str
    total_failures: int
    max_in_window: int
    first_failure: datetime
    last_failure: datetime
    target_users: list[str]
    succeeded_after: bool


@dataclass
class AnalysisResult:
    """Підсумок аналізу журналу."""

    total_events: int
    time_start: datetime | None
    time_end: datetime | None
    findings: list[BruteforceFinding]

    @property
    def blocklist(self) -> list[str]:
        """Відсортований список IP для блокування."""
        return sorted(finding.ip for finding in self.findings)


def parse_line(line: str, year: int) -> AuthEvent | None:
    """Розібрати рядок auth.log; повернути None, якщо він не підходить."""
    match = AUTH_RE.match(line)
    if match is None:
        return None
    month = MONTHS.get(match["month"])
    if month is None:
        return None
    hour, minute, second = (int(part) for part in match["time"].split(":"))
    try:
        timestamp = datetime(
            year, month, int(match["day"]), hour, minute, second, tzinfo=timezone.utc
        )
    except ValueError:
        return None
    return AuthEvent(
        timestamp=timestamp,
        host=match["host"],
        user=match["user"],
        ip=match["ip"],
        success=match["result"] == "Accepted",
        invalid_user=match["invalid"] is not None,
    )


def iter_events(path: Path, year: int, stats: ParseStats) -> Iterator[AuthEvent]:
    """Генератор подій: файл читається порядково, без завантаження в пам'ять."""
    with path.open(encoding="utf-8", errors="replace") as file:
        for line in file:
            if not line.strip():
                continue
            stats.total_lines += 1
            event = parse_line(line, year)
            if event is None:
                stats.skipped_lines += 1
                continue
            yield event


def max_in_window(times: list[datetime], window: timedelta) -> int:
    """Максимальна кількість подій у будь-якому вікні заданої тривалості."""
    best = 0
    left = 0
    for right, current in enumerate(times):
        while current - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(
    events: Iterator[AuthEvent], threshold: int, window_min: int
) -> AnalysisResult:
    """Знайти IP з кількістю невдалих спроб, більшою за поріг, у вікні."""
    failures: defaultdict[str, list[datetime]] = defaultdict(list)
    successes: defaultdict[str, list[datetime]] = defaultdict(list)
    users: defaultdict[str, set[str]] = defaultdict(set)
    total = 0
    time_start: datetime | None = None
    time_end: datetime | None = None

    for event in events:
        total += 1
        time_start = min(time_start or event.timestamp, event.timestamp)
        time_end = max(time_end or event.timestamp, event.timestamp)
        if event.success:
            successes[event.ip].append(event.timestamp)
        else:
            failures[event.ip].append(event.timestamp)
            users[event.ip].add(event.user)

    window = timedelta(minutes=window_min)
    findings = []
    for ip, times in failures.items():
        times.sort()
        peak = max_in_window(times, window)
        if peak <= threshold:
            continue
        findings.append(
            BruteforceFinding(
                ip=ip,
                total_failures=len(times),
                max_in_window=peak,
                first_failure=times[0],
                last_failure=times[-1],
                target_users=sorted(users[ip]),
                succeeded_after=any(t > times[0] for t in successes[ip]),
            )
        )
    findings.sort(key=lambda item: item.total_failures, reverse=True)
    return AnalysisResult(total, time_start, time_end, findings)


def report_to_dict(result: AnalysisResult, threshold: int, window_min: int) -> dict:
    """Зібрати словник для JSON-звіту."""
    return {
        "threshold": threshold,
        "window_min": window_min,
        "total_events": result.total_events,
        "time_start": result.time_start.isoformat() if result.time_start else None,
        "time_end": result.time_end.isoformat() if result.time_end else None,
        "findings": [
            {
                "ip": f.ip,
                "total_failures": f.total_failures,
                "max_in_window": f.max_in_window,
                "first_failure": f.first_failure.isoformat(),
                "last_failure": f.last_failure.isoformat(),
                "target_users": f.target_users,
                "succeeded_after": f.succeeded_after,
            }
            for f in result.findings
        ],
        "blocklist": result.blocklist,
    }


def print_report(result: AnalysisResult, threshold: int, window_min: int) -> None:
    """Вивести підсумок у консоль і записати тривоги через logging.error."""
    print("\n=== SSH Bruteforce Detection Results ===")
    print(f"Failed Attempts Threshold: >{threshold} attempts in {window_min} minutes")
    if not result.findings:
        print("No bruteforce activity detected.")
        return
    for finding in result.findings:
        logger.error(
            "Bruteforce Detected! IP: %s | Total Failures: %d | Target Users: %s",
            finding.ip,
            finding.total_failures,
            ", ".join(finding.target_users),
        )
        if finding.succeeded_after:
            logger.error(
                "IP %s later logged in successfully: account may be compromised!",
                finding.ip,
            )
    print("\n=== Recommended Blocklist (IPs) ===")
    for ip in result.blocklist:
        print(ip)


def write_json(path: Path, data: dict) -> None:
    """Записати звіт у JSON, створивши каталог за потреби."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


def positive_int(value: str) -> int:
    """Тип argparse: ціле число більше нуля."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return number


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Додати CLI-аргументи команди analyze."""
    parser.add_argument(
        "--auth-log", type=Path, default=DEFAULT_LOG, help="шлях до auth.log"
    )
    parser.add_argument(
        "--threshold",
        type=positive_int,
        default=DEFAULT_THRESHOLD,
        help="поріг: тривога, якщо невдалих спроб БІЛЬШЕ за це число",
    )
    parser.add_argument(
        "--window-min",
        type=positive_int,
        default=DEFAULT_WINDOW_MIN,
        help="часове вікно в хвилинах",
    )
    parser.add_argument(
        "--output-json", type=Path, default=None, help="шлях до JSON-звіту"
    )
    parser.add_argument(
        "--year",
        type=positive_int,
        default=datetime.now(timezone.utc).year,
        help="рік для міток часу (в auth.log його немає)",
    )


def run(args: argparse.Namespace) -> int:
    """Виконати аналіз; повернути код завершення процесу."""
    path: Path = args.auth_log
    logger.info("Analyzing authentication events in %s...", path)
    stats = ParseStats()
    try:
        result = analyze(
            iter_events(path, args.year, stats), args.threshold, args.window_min
        )
    except FileNotFoundError:
        logger.error("Log file not found: %s", path)
        return 1
    except PermissionError:
        logger.error("No permission to read: %s", path)
        return 1
    except OSError as error:
        logger.error("Cannot read %s: %s", path, error)
        return 1

    if result.time_start and result.time_end:
        time_format = "%Y-%m-%d %H:%M:%S"
        logger.info(
            "Processed %d lines (Time range: %s - %s)",
            stats.total_lines,
            result.time_start.strftime(time_format),
            result.time_end.strftime(time_format),
        )
    if stats.skipped_lines:
        logger.warning("Skipped %d unrecognized lines", stats.skipped_lines)

    print_report(result, args.threshold, args.window_min)

    if args.output_json:
        data = report_to_dict(result, args.threshold, args.window_min)
        try:
            write_json(args.output_json, data)
        except OSError as error:
            logger.error("Cannot write report %s: %s", args.output_json, error)
            return 1
        logger.info("Exported report to %s", args.output_json)
    return 0
