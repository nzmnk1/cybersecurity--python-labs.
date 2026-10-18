"""Точка входу ЛР №2: команди demo та analyze."""

import argparse
import logging
import sys

from labs.lab02 import task2


def build_parser() -> argparse.ArgumentParser:
    """Створити парсер із підкомандами demo та analyze."""
    parser = argparse.ArgumentParser(prog="python -m labs.lab02.main")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="демонстрація ООП (Завдання 1)")
    analyze = subparsers.add_parser("analyze", help="аналіз SSH auth.log (Завдання 2)")
    task2.add_arguments(analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Розібрати аргументи та виконати вибрану команду."""
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        from labs.lab02 import task1

        task1.demo()
        return 0
    return task2.run(args)


if __name__ == "__main__":
    sys.exit(main())
