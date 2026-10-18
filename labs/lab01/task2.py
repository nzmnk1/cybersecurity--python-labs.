    import os
    import sys

    sys.path.append(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
    )
    from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER
    users = {
        "ciso_office": {
            "role": "ciso",
            "clearance": 4,
            "department": "Executive",
            "active": True,
        },
        "threat_hunter": {
            "role": "threat_analyst",
            "clearance": 3,
            "department": "Threat Intel",
            "active": True,
        },
        "junior_dev": {
            "role": "junior_developer",
            "clearance": 2,
            "department": "Development",
            "active": True,
        },
        "visitor_acc": {
            "role": "visitor",
            "clearance": 1,
            "department": "Guest",
            "active": True,
        },
        "legacy_sys": {
            "role": "legacy",
            "clearance": 2,
            "department": "Legacy",
            "active": False,
        },
    }

    resources = [
        ("threat_intelligence", 4),
        ("malware_samples", 3),
        ("coding_guidelines", 2),
        ("visitor_wifi", 1),
        ("strategic_plans", 4),
        ("demo_environment", 1),
        ("risk_assessments", 3),
        ("crypto_keys", 4),
        ("api_documentation", 2),
        ("guest_portal", 1),
    ]

    security_levels = ("Guest", "Employee", "Privileged", "Executive")
    blocked_users = {"legacy_sys", "malicious_user", "expired_guest"}

    def display_resources(
        resource_list: list[tuple[str, int]], levels: tuple[str, ...]
    ) -> None:
        print("--- Список ресурсів системи (Крок 2) ---")
        for res_name, level_num in resource_list:
            level_text = levels[level_num - 1]
            print(f"Ресурс: {res_name:<24} Рівень безпеки: {level_text}")
        print()
    def check_access(
        username: str,
        resource: tuple[str, int],
        users_dict: dict,
        blocked_set: set,
    ) -> tuple[str, str]:
        _, res_level = resource

        if username not in users_dict:
            return "DENY", "User not found"


        if username in blocked_set:
            return "DENY", "User is blocked"

        user_info = users_dict[username]

        if not user_info.get("active", False):
            return "DENY", "Account inactive"


        user_clearance = user_info.get("clearance", 0)
        if user_clearance >= res_level:
            return "ALLOW", ""
        return "DENY", "Insufficient clearance"

    def run_access_control(
        users_dict: dict,
        resource_list: list[tuple[str, int]],
        blocked_set: set,
    ) -> None:
        print("--- Результати перевірки доступу (Крок 4) ---")
        for username in users_dict:
            for resource in resource_list:
                status, reason = check_access(
                    username, resource, users_dict, blocked_set
                )
                res_name = resource[0]

                if status == "ALLOW":
                    print(f"user=[{username}] resource=[{res_name}] -> ALLOW")
                else:
                    print(
                        f"user=[{username}] resource=[{res_name}] -> DENY ({reason})"
                    )

    def main() -> None:

        print(
            f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
        )

        display_resources(resources, security_levels)

        run_access_control(users, resources, blocked_users)
    if __name__ == "__main__":
        main()