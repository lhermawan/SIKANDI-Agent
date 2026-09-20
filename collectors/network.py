import psutil

class NetworkCollector:
    def collect(self):
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.status == 'ESTABLISHED':
                    conns.append({
                        'laddr_ip': c.laddr.ip if c.laddr else None,
                        'laddr_port': c.laddr.port if c.laddr else None,
                        'raddr_ip': c.raddr.ip if c.raddr else None,
                        'raddr_port': c.raddr.port if c.raddr else None,
                        'status': c.status,
                        'pid': c.pid
                    })
        except Exception:
            pass
        return conns
