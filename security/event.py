import uuid
import time
import platform

class SecurityEventBuilder:
    @staticmethod
    def build(event_type, action, severity="info", **kwargs):
        ev = {
            "event_id": str(uuid.uuid4()),
            "timestamp": int(time.time()),
            "hostname": platform.node(),
            "event_type": event_type,
            "action": action,
            "severity": severity,
            "username": kwargs.get("username", "N/A"),
            "source_ip": kwargs.get("source_ip", "N/A"),
            "process_name": kwargs.get("process_name", "N/A"),
            "reason": kwargs.get("reason", "Anomalous behavior detected")
        }
        ev.update(kwargs)
        return ev
