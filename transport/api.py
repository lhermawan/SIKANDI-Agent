import requests
import socket
import logging

logger = logging.getLogger(__name__)

class ApiClient:
    def __init__(self, config):
        self.config = config
        self.base_url = config.get('api.url')
        self.token = config.get('api.token')
        self.timeout = config.get('api.timeout', 10)
        
    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        
    def register(self):
        if not self.token or str(self.token).strip() == "" or "MASUKKAN_TOKEN_ANDA_DISINI" in str(self.token):
            print("=== SIKANDI Agent Simulator ===")
            print("[-] Token belum disetel di config.yaml.")
            reg_token = input("Masukkan Registration Token: ").strip()
            self.token = reg_token
            
            try:
                print("[1] Registrasi Agent...")
                resp = requests.post(f"{self.base_url}/register", json={
                    "registration_token": reg_token,
                    "hostname": socket.gethostname(),
                    "os": "Cross-Platform",
                    "os_version": "2.0",
                    "agent_version": "2.0.0"
                }, timeout=self.timeout)
                
                if resp.status_code == 201:
                    data = resp.json()
                    agent_id = data.get('agent_id')
                    print(f"Registrasi Berhasil! Agent ID: {agent_id}")
                    print("\n>>> PENTING: Buka browser SIKANDI, masuk ke Server Agents.")
                    print(">>> Klik tombol 'Approve' lalu COPY token Sanctum yang muncul.")
                    
                    sanctum_token = input("\nMasukkan Agent Token (Sanctum) yang baru digenerate: ").strip()
                    self.token = sanctum_token
                    
                    # Update config.yaml with new token automatically
                    import yaml
                    try:
                        with open(self.config.path, 'r') as f:
                            cfg = yaml.safe_load(f)
                        cfg['api']['token'] = sanctum_token
                        with open(self.config.path, 'w') as f:
                            yaml.safe_dump(cfg, f, default_flow_style=False)
                        print("Token berhasil disimpan ke config.yaml. Melanjutkan monitoring...")
                    except Exception as e:
                        print("Gagal menyimpan ke config.yaml, menggunakan token sementara di memori.")
                    
                    return True
                else:
                    logger.error(f"Registrasi gagal: {resp.text}")
                    return False
            except Exception as e:
                logger.error(f"Register error: {e}")
                return False
                
        # Jika token sudah ada di config, anggap sukses (sudah memiliki sanctum token)
        return True

    def send_heartbeat(self):
        try:
            requests.post(f"{self.base_url}/heartbeat", headers=self._headers(), timeout=self.timeout)
            logger.info("Heartbeat sent.")
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")

    def send_metrics(self, metrics):
        try:
            requests.post(f"{self.base_url}/metrics", headers=self._headers(), json=metrics, timeout=self.timeout)
            cpu = metrics.get('cpu_usage', 0)
            ram = metrics.get('memory_usage', 0)
            logger.info(f"Metrics sent: CPU {cpu}% | RAM {ram}%")
        except Exception as e:
            logger.error(f"Metrics failed: {e}")

    def send_services(self, services):
        try:
            requests.post(f"{self.base_url}/services", headers=self._headers(), json={"services": services}, timeout=self.timeout)
            names = [s['name'] for s in services] if services else []
            logger.info(f"Services status sent: {', '.join(names)}")
        except Exception as e:
            logger.error(f"Services failed: {e}")
            
    def send_security_events(self, events):
        try:
            for ev in events:
                payload = {
                    "type": "security_event",
                    "severity": ev.get("severity", "info"),
                    "message": f"Security Event: {ev.get('action')} by {ev.get('username')}",
                    "payload": ev
                }
                requests.post(f"{self.base_url}/events", headers=self._headers(), json=payload, timeout=self.timeout)
            logger.warning(f"Sent {len(events)} security events.")
            return True
        except Exception as e:
            logger.error(f"Events failed: {e}")
            return False

    def fetch_blacklist(self):
        try:
            resp = requests.get(f"{self.base_url}/blacklist", headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json().get('blacklist', [])
            return []
        except Exception as e:
            logger.error(f"Failed to fetch blacklist: {e}")
            return []

    def fetch_commands(self):
        try:
            resp = requests.get(f"{self.base_url}/commands", headers=self._headers(), timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json().get('commands', [])
            return []
        except Exception as e:
            logger.error(f"Failed to fetch commands: {e}")
            return []
            
    def send_command_result(self, command_id, result):
        try:
            payload = {
                "command_id": command_id,
                "result": result
            }
            resp = requests.post(f"{self.base_url}/commands/{command_id}/result", headers=self._headers(), json=payload, timeout=self.timeout)
            if resp.status_code in [200, 201]:
                logger.info(f"Successfully sent result for command {command_id}")
                return True
            else:
                logger.error(f"Failed to send result for command {command_id}: HTTP {resp.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error sending command result: {e}")
            return False
