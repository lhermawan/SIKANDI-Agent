import os
import hashlib

class FIMCollector:
    def __init__(self, config):
        self.paths = config.get('security.file_integrity.paths', ['/etc/passwd', '/etc/shadow'])
        self.hashes = {}
        self._initialize_hashes()
        
    def _initialize_hashes(self):
        for path in self.paths:
            self.hashes[path] = self._hash_file(path)
            
    def _hash_file(self, path):
        if not os.path.exists(path):
            return None
        try:
            hasher = hashlib.sha256()
            with open(path, 'rb') as f:
                buf = f.read(65536)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = f.read(65536)
            return hasher.hexdigest()
        except Exception:
            return None
            
    def collect(self):
        events = []
        for path in self.paths:
            current_hash = self._hash_file(path)
            if self.hashes.get(path) != current_hash:
                if current_hash is None:
                    action = "deleted"
                elif self.hashes.get(path) is None:
                    action = "created"
                else:
                    action = "modified"
                    
                events.append({
                    "event_type": "file_integrity",
                    "action": action,
                    "file": path,
                    "old_hash": self.hashes.get(path),
                    "new_hash": current_hash,
                    "severity": "high"
                })
                self.hashes[path] = current_hash
        return events
