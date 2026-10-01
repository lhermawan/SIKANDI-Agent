class SuspiciousNetworkDetector:
    def __init__(self, config=None):
        self.suspicious_ports = [4444, 5555, 6666, 7777, 9999, 31337] # Common backdoor/C2 ports
        
        self.whitelisted_ports = []
        if config and 'security' in config and 'network_monitoring' in config['security']:
            net_config = config['security']['network_monitoring']
            if 'whitelisted_ports' in net_config:
                self.whitelisted_ports = net_config['whitelisted_ports']
        
    def analyze(self, connections):
        alerts = []
        for c in connections:
            rport = c.get('raddr_port')
            if rport in self.suspicious_ports and rport not in self.whitelisted_ports:
                alerts.append({
                    "event_type": "network",
                    "action": "suspicious_connection",
                    "source_ip": c.get('laddr_ip'),
                    "remote_ip": c.get('raddr_ip'),
                    "process_pid": c.get('pid'),
                    "reason": f"Connection to known suspicious port: {rport}",
                    "severity": "high"
                })
        return alerts
