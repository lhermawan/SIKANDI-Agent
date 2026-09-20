class SuspiciousLoginDetector:
    def __init__(self):
        self.known_ips = set()
        
    def analyze(self, events):
        alerts = []
        for ev in events:
            if ev.get('event_type') == 'login' and ev.get('action') in ['success', 'login_success']:
                ip = ev.get('source_ip')
                user = ev.get('username')
                if ip and ip not in self.known_ips:
                    # If this is the very first time we see an IP and it's successful, 
                    # we could flag it. But to avoid spam, we just record it.
                    # We flag if user is root and IP is new.
                    if user == 'root' and len(self.known_ips) > 0:
                        alerts.append({
                            "event_type": "suspicious_login",
                            "action": "detected",
                            "username": user,
                            "source_ip": ip,
                            "reason": "Root login from entirely new IP address",
                            "severity": "medium"
                        })
                    self.known_ips.add(ip)
        return alerts
