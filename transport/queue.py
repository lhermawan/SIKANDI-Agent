class EventQueue:
    def __init__(self, config):
        self.queue = []
        self.max_size = config.get('queue.max_size', 10000)
        
    def add(self, event):
        if len(self.queue) < self.max_size:
            self.queue.append(event)
            
    def get_batch(self, size=50):
        return self.queue[:size]
        
    def clear_batch(self, events):
        self.queue = [e for e in self.queue if e not in events]
