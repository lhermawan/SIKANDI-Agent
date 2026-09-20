class PrivilegeEscalationDetector:
    def __init__(self):
        self.seen_sudoers = set()
        
    def analyze(self, processes):
        alerts = []
        for p in processes:
            name = str(p.get('name', '')).lower()
            cmd = " ".join(p.get('cmdline', []) or []).lower()
            user = p.get('username')
            pid = p.get('pid')
            
            # Detect suspicious sudo usage or su
            if (name == 'sudo' or name == 'su') and pid not in self.seen_sudoers:
                self.seen_sudoers.add(pid)
                if 'bash' in cmd or 'sh' in cmd:
                    alerts.append({
                        "event_type": "privilege_escalation",
                        "action": "attempt",
                        "username": user,
                        "process_name": name,
                        "cmdline": cmd,
                        "reason": "User attempting to spawn root shell via sudo/su",
                        "severity": "medium"
                    })
                    
        # keep memory small
        if len(self.seen_sudoers) > 1000:
            self.seen_sudoers.clear()
            
        return alerts
