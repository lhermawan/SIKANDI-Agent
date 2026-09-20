class SuspiciousNetworkDetector:
    def __init__(self):
        self.suspicious_ports = [4444, 5555, 6666, 7777, 9999, 31337] # Common backdoor/C2 ports
        
    def analyze(self, connections):
        alerts = []
        for c in connections:
            rport = c.get('raddr_port')
            if rport in self.suspicious_ports:
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
