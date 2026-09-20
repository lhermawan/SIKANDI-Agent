import os
import re
import logging

logger = logging.getLogger(__name__)

class Fail2banCollector:
    def __init__(self):
        self.log_file = "/var/log/fail2ban.log"
        self.ban_pattern = re.compile(r'\[([^\]]+)\]\s+(Ban|Unban)\s+([0-9\.]+)')
        self.last_pos = 0
        
        # Inisialisasi ke akhir file agar tidak mengulang baca log lama
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    f.seek(0, os.SEEK_END)
                    self.last_pos = f.tell()
            except Exception as e:
                logger.error(f"Error initializing Fail2banCollector: {e}")

    def collect(self):
        events = []
        if not os.path.exists(self.log_file):
            return events

        try:
            with open(self.log_file, 'r') as f:
                f.seek(self.last_pos)
                lines = f.readlines()
                self.last_pos = f.tell()

                for line in lines:
                    match = self.ban_pattern.search(line)
                    if match:
                        jail_name = match.group(1)
                        action = match.group(2)
                        ip_address = match.group(3)

                        event_type = f"FAIL2BAN_{action.upper()}"
                        events.append({
                            "event_type": event_type,
                            "action": action.upper(),
                            "severity": "HIGH" if action == "Ban" else "LOW",
                            "reason": f"Fail2ban {action.lower()}ned IP {ip_address} in jail {jail_name}",
                            "source_ip": ip_address,
                            "process_name": "fail2ban",
                            "username": "system"
                        })
        except Exception as e:
            logger.error(f"Error reading fail2ban log: {e}")
            
        return events
