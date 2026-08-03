import re


class ThreatDetector:

    def detect(self, log):

        message = log["message"]
        service = log["service"]

        event = None
        severity = None
        category = None

        user = "Unknown"
        ip = "-"

        # -------------------------
        # SSH Failed Login
        # -------------------------
        if service == "sshd" and "Failed password" in message:

            event = "Failed SSH Login"
            severity = "HIGH"
            category = "Remote Access"

            user_match = re.search(r"for (?:invalid user )?(\w+)", message)
            ip_match = re.search(r"from ([0-9.]+)", message)

            if user_match:
                user = user_match.group(1)

            if ip_match:
                ip = ip_match.group(1)

        # -------------------------
        # SSH Success
        # -------------------------
        elif service == "sshd" and "Accepted password" in message:

            event = "Successful SSH Login"
            severity = "LOW"
            category = "Remote Access"

            user_match = re.search(r"for (\w+)", message)
            ip_match = re.search(r"from ([0-9.]+)", message)

            if user_match:
                user = user_match.group(1)

            if ip_match:
                ip = ip_match.group(1)

        # -------------------------
        # GUI Login
        # -------------------------
        elif service == "gdm-password":

            if "session opened for user" in message:

                event = "GUI Login"
                severity = "LOW"
                category = "Authentication"

                user_match = re.search(r"user (\w+)", message)

                if user_match:
                    user = user_match.group(1)

        # -------------------------
        # sudo
        # -------------------------
        elif service == "sudo":

            if "COMMAND=" in message:

                event = "sudo Command"
                severity = "MEDIUM"
                category = "Privilege Escalation"

                user_match = re.search(r"^(\w+)", message)

                if user_match:
                    user = user_match.group(1)

        # -------------------------
        # pkexec
        # -------------------------
        elif service == "pkexec":

            event = "pkexec Executed"
            severity = "HIGH"
            category = "Privilege Escalation"

            user_match = re.search(r"^(\w+):", message)

            if user_match:
                user = user_match.group(1)

        else:

            return None

        return {

            "timestamp": f"{log['month']} {log['day']} {log['time']}",
            "service": service,
            "event": event,
            "severity": severity,
            "category": category,
            "user": user,
            "ip": ip,
            "hostname": log["host"],
            "message": message

        }
