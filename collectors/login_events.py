import platform
import os
import time

class LoginCollector:
    def __init__(self):
        self.os_type = platform.system()
        self.last_pos = 0
        self.auth_file = '/var/log/auth.log' if os.path.exists('/var/log/auth.log') else '/var/log/secure'
        if self.os_type == 'Linux' and os.path.exists(self.auth_file):
            self.last_pos = os.path.getsize(self.auth_file)
            
    def collect(self):
        events = []
        if self.os_type == 'Linux' and os.path.exists(self.auth_file):
            try:
                with open(self.auth_file, 'r') as f:
                    f.seek(self.last_pos)
                    lines = f.readlines()
                    self.last_pos = f.tell()
                    for line in lines:
                        if 'sshd' in line:
                            if 'Failed password' in line:
                                parts = line.split()
                                user_idx = parts.index('for') + 1
                                # sometimes "invalid user" is present
                                if parts[user_idx] == 'invalid':
                                    user_idx += 2
                                user = parts[user_idx]
                                ip_idx = parts.index('from') + 1
                                ip = parts[ip_idx]
                                events.append({
                                    'event_type': 'login',
                                    'action': 'failed',
                                    'username': user,
                                    'source_ip': ip,
                                    'severity': 'low'
                                })
                            elif 'Accepted password' in line or 'Accepted publickey' in line:
                                parts = line.split()
                                user_idx = parts.index('for') + 1
                                user = parts[user_idx]
                                ip_idx = parts.index('from') + 1
                                ip = parts[ip_idx]
                                events.append({
                                    'event_type': 'login',
                                    'action': 'success',
                                    'username': user,
                                    'source_ip': ip,
                                    'severity': 'info'
                                })
            except Exception:
                pass
        return events
