import time
from collections import defaultdict, deque


class AnomalyDetector:

    def __init__(self):
        self.login_history = defaultdict(deque)
        self.known_users = set()
        self.known_services = set()

        self.login_window = 300  # 5 minutes

    def analyze_login(self, event):
        """
        Detect unusual login behaviour.

        Expected event:
        {
            "username": "root",
            "source_ip": "10.27.70.10",
            "action": "failed",
            "timestamp": 1234567890
        }
        """

        username = event.get("username")
        source_ip = event.get("source_ip")
        action = event.get("action")
        timestamp = event.get("timestamp", time.time())

        if not username or not source_ip:
            return None

        key = source_ip

        history = self.login_history[key]

        # Remove events older than 5 minutes
        while history and timestamp - history[0]["timestamp"] > self.login_window:
            history.popleft()

        history.append({
            "username": username,
            "action": action,
            "timestamp": timestamp,
        })

        failed = [
            item for item in history
            if item["action"] == "failed"
        ]

        unique_users = {
            item["username"]
            for item in failed
        }

        # Password spraying / username enumeration
        if len(unique_users) >= 5:
            return {
                "type": "password_spraying",
                "severity": "high",
                "risk_score": 70,
                "source_ip": source_ip,
                "username_count": len(unique_users),
                "failed_attempts": len(failed),
                "reason": (
                    f"{len(unique_users)} different usernames "
                    f"attempted from the same source IP"
                ),
            }

        # Brute force
        if len(failed) >= 20:
            return {
                "type": "brute_force",
                "severity": "critical",
                "risk_score": 90,
                "source_ip": source_ip,
                "failed_attempts": len(failed),
                "reason": (
                    f"{len(failed)} failed login attempts "
                    f"within 5 minutes"
                ),
            }

        if len(failed) >= 10:
            return {
                "type": "brute_force",
                "severity": "high",
                "risk_score": 75,
                "source_ip": source_ip,
                "failed_attempts": len(failed),
                "reason": (
                    f"{len(failed)} failed login attempts "
                    f"within 5 minutes"
                ),
            }

        if len(failed) >= 5:
            return {
                "type": "brute_force",
                "severity": "medium",
                "risk_score": 50,
                "source_ip": source_ip,
                "failed_attempts": len(failed),
                "reason": (
                    f"{len(failed)} failed login attempts "
                    f"within 5 minutes"
                ),
            }

        return None

    def analyze_users(self, users):
        """
        Detect newly discovered user accounts.
        """

        anomalies = []

        current_users = {
            user.get("username")
            for user in users
            if user.get("username")
        }

        if not self.known_users:
            self.known_users = current_users
            return []

        new_users = current_users - self.known_users

        for username in new_users:
            anomalies.append({
                "type": "new_user",
                "severity": "high",
                "risk_score": 70,
                "username": username,
                "reason": f"New user account detected: {username}",
            })

        self.known_users.update(current_users)

        return anomalies

    def analyze_services(self, services):
        """
        Detect newly discovered services.
        """

        anomalies = []

        current_services = {
            service.get("name")
            for service in services
            if service.get("name")
        }

        if not self.known_services:
            self.known_services = current_services
            return []

        new_services = current_services - self.known_services

        for service in new_services:
            anomalies.append({
                "type": "new_service",
                "severity": "medium",
                "risk_score": 50,
                "service": service,
                "reason": f"New service detected: {service}",
            })

        self.known_services.update(current_services)

        return anomalies