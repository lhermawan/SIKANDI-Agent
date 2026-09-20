class SuspiciousProcessDetector:
    def __init__(self):
        self.suspicious_names = ['nc', 'ncat', 'socat', 'mimikatz.exe', 'powershell.exe', 'cmd.exe', 'wget', 'curl']
        self.seen_pids = set()
        
    def analyze(self, processes):
        alerts = []
        for p in processes:
            pid = p.get('pid')
            if pid in self.seen_pids:
                continue
            self.seen_pids.add(pid)
            
            name = str(p.get('name', '')).lower()
            cmdline = " ".join(p.get('cmdline', []) or []).lower()
            
            if name in self.suspicious_names or 'reverse_tcp' in cmdline or 'stratum' in cmdline:
                alerts.append({
                    "event_type": "suspicious_process",
                    "action": "started",
                    "process_name": name,
                    "cmdline": cmdline,
                    "username": p.get('username'),
                    "severity": "medium"
                })
        return alerts
