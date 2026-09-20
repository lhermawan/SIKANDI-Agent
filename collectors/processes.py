import psutil
import time

class ProcessCollector:
    def collect(self):
        procs = []
        for p in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username']):
            try:
                info = p.info
                info['timestamp'] = time.time()
                procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return procs
