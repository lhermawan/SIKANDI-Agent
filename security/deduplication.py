import time

class Deduplicator:
    def __init__(self, config):
        self.seen = {}
        self.cooldown = 60
        
    def is_duplicate(self, event):
        sig = f"{event.get('event_type')}_{event.get('username')}_{event.get('source_ip')}"
        now = time.time()
        if sig in self.seen and now - self.seen[sig] < self.cooldown:
            return True
        self.seen[sig] = now
        return False
