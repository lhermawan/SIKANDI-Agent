import time

class BruteForceDetector:
    def __init__(self, config):
        self.window = config.get('security.brute_force.window_seconds', 300)
        self.threshold = config.get('security.brute_force.threshold', 5)
        self.failed_logins = {} # ip -> list of timestamps
        
    def analyze(self, events):
        alerts = []
        now = time.time()
        for ev in events:
            if ev.get('event_type') == 'login' and ev.get('action') == 'failed':
                ip = ev.get('source_ip')
                if not ip: continue
                if ip not in self.failed_logins:
                    self.failed_logins[ip] = []
                self.failed_logins[ip].append(now)
                
                # Cleanup old
                self.failed_logins[ip] = [t for t in self.failed_logins[ip] if now - t <= self.window]
                
                count = len(self.failed_logins[ip])
                if count >= self.threshold:
                    alerts.append({
                        "event_type": "brute_force",
                        "action": "detected",
                        "source_ip": ip,
                        "username": ev.get('username'),
                        "count": count,
                        "severity": "high" if count < 20 else "critical"
                    })
        return alerts
