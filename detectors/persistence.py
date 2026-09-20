import os
import platform

class PersistenceDetector:
    def __init__(self):
        self.os_type = platform.system()
        self.known_crons = set()
        self.initialized = False
        
    def analyze(self, _): # Takes no input, it checks system state
        alerts = []
        if self.os_type == 'Linux':
            cron_dirs = ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/crontabs/']
            current_crons = set()
            for cdir in cron_dirs:
                if os.path.isfile(cdir):
                    current_crons.add(cdir)
                elif os.path.isdir(cdir):
                    try:
                        for f in os.listdir(cdir):
                            current_crons.add(os.path.join(cdir, f))
                    except Exception:
                        pass
            
            if not self.initialized:
                self.known_crons = current_crons
                self.initialized = True
            else:
                new_crons = current_crons - self.known_crons
                for nc in new_crons:
                    alerts.append({
                        "event_type": "persistence",
                        "action": "created",
                        "file": nc,
                        "reason": "New cron job / persistence mechanism detected",
                        "severity": "medium"
                    })
                self.known_crons = current_crons
                
        return alerts
