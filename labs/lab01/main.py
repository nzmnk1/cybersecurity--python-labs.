
import subprocess
import sys


def run_all() -> None:
    tasks = ["task1.py", "task2.py", "task3.py"]
    for task in tasks:
        print(f"\n{'=' * 20} ЗАПУСК {task} {'=' * 20}")
        subprocess.run([sys.executable, f"{task}"], check=False)


if __name__ == "__main__":
    run_all()