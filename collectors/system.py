import psutil
import platform
import time

class SystemCollector:
    def collect(self):
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_total": psutil.virtual_memory().total,
            "memory_used": psutil.virtual_memory().used,
            "memory_usage": psutil.virtual_memory().percent,
            "disk_total": psutil.disk_usage('/').total,
            "disk_used": psutil.disk_usage('/').used,
            "disk_usage": psutil.disk_usage('/').percent,
            "uptime_seconds": int(time.time() - psutil.boot_time()),
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.release()
        }
