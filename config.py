import yaml
import os

class Config:
    def __init__(self, path='config.yaml'):
        self.path = path
        self.data = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            return {
                'agent': {'heartbeat_interval': 60, 'metrics_interval': 60, 'security_interval': 10},
                'api': {'url': 'https://sikandi.ciamiskab.go.id/api/v1/agent', 'token': '', 'timeout': 10},
                'queue': {'max_size': 10000}
            }
        with open(self.path, 'r') as f:
            return yaml.safe_load(f)

    def get(self, key_path, default=None):
        keys = key_path.split('.')
        val = self.data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val
