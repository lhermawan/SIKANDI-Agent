import time
import argparse
import logging
from config import Config
from transport.api import ApiClient
from transport.queue import EventQueue
from collectors.system import SystemCollector
from collectors.services import ServiceCollector
from collectors.disk_manager import DiskManager
from security.correlation import CorrelationEngine
from security.deduplication import Deduplicator
import threading
import subprocess

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
logger = logging.getLogger(__name__)

class SikandiAgent:
    def __init__(self, test_mode=False):
        self.config = Config()
        self.test_mode = test_mode
        self.api = ApiClient(self.config)
        self.queue = EventQueue(self.config)
        self.system = SystemCollector()
        self.services = ServiceCollector()
        self.disk_manager = DiskManager()
        self.correlation = CorrelationEngine()
        self.deduplicator = Deduplicator(self.config)
        
    def start(self):
        logger.info("=== SIKANDI Intelligent Security Monitoring Agent ===")
        if not self.api.register():
            logger.error("Registration failed. Exiting.")
            return

        logger.info("Agent registered. Starting collectors...")
        
        # Start background threads for heartbeat, metrics, security, and actions
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._metrics_loop, daemon=True).start()
        threading.Thread(target=self._security_loop, daemon=True).start()
        threading.Thread(target=self._queue_flush_loop, daemon=True).start()
        threading.Thread(target=self._blacklist_loop, daemon=True).start()
        threading.Thread(target=self._command_loop, daemon=True).start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Agent stopped.")

    def _heartbeat_loop(self):
        while True:
            self.api.send_heartbeat()
            time.sleep(self.config.get('agent.heartbeat_interval', 60))

    def _metrics_loop(self):
        while True:
            metrics = self.system.collect()
            self.api.send_metrics(metrics)
            
            services = self.services.collect()
            self.api.send_services(services)
            
            time.sleep(self.config.get('agent.metrics_interval', 60))

    def _security_loop(self):
        # Initialize collectors/detectors
        from collectors.login_events import LoginCollector
        from collectors.processes import ProcessCollector
        from collectors.network import NetworkCollector
        from collectors.file_integrity import FIMCollector
        from collectors.fail2ban_collector import Fail2banCollector
        
        from detectors.brute_force import BruteForceDetector
        from detectors.suspicious_process import SuspiciousProcessDetector
        from detectors.suspicious_network import SuspiciousNetworkDetector
        from detectors.persistence import PersistenceDetector
        from detectors.privilege_escalation import PrivilegeEscalationDetector
        from detectors.suspicious_login import SuspiciousLoginDetector
        
        from security.risk_score import RiskScorer
        
        login_coll = LoginCollector()
        proc_coll = ProcessCollector()
        net_coll = NetworkCollector()
        fim_coll = FIMCollector(self.config)
        f2b_coll = Fail2banCollector()
        
        brute_det = BruteForceDetector(self.config)
        proc_det = SuspiciousProcessDetector()
        net_det = SuspiciousNetworkDetector()
        pers_det = PersistenceDetector()
        priv_det = PrivilegeEscalationDetector()
        login_det = SuspiciousLoginDetector()
        
        scorer = RiskScorer()
        
        while True:
            if self.test_mode:
                self._run_test_mode()
            else:
                try:
                    events = []
                    # 1. Collect
                    logins = login_coll.collect()
                    events.extend(logins)
                    
                    procs = proc_coll.collect()
                    net_conns = net_coll.collect()
                    
                    fims = fim_coll.collect()
                    events.extend(fims)
                    
                    f2b_events = f2b_coll.collect()
                    events.extend(f2b_events)
                    
                    # 2. Detect
                    events.extend(brute_det.analyze(logins))
                    events.extend(login_det.analyze(logins))
                    events.extend(proc_det.analyze(procs))
                    events.extend(priv_det.analyze(procs))
                    events.extend(net_det.analyze(net_conns))
                    events.extend(pers_det.analyze(None))
                    
                    # 2.5 Correlate locally (Agent-side)
                    events.extend(self.correlation.analyze(events))
                    
                    # 3. Normalize, Score & Queue
                    import platform
                    import uuid
                    import time
                    current_host = platform.node()
                    current_time = int(time.time())
                    
                    for ev in events:
                        ev['event_id'] = str(uuid.uuid4())
                        ev['hostname'] = ev.get('hostname', current_host)
                        ev['timestamp'] = ev.get('timestamp', current_time)
                        ev['event_type'] = ev.get('event_type', 'unknown')
                        ev['action'] = ev.get('action', 'unknown')
                        ev['username'] = ev.get('username', 'N/A')
                        ev['source_ip'] = ev.get('source_ip', 'N/A')
                        ev['process'] = ev.get('process_name', 'N/A')
                        ev['severity'] = ev.get('severity', 'info')
                        ev['reason'] = ev.get('reason', 'Detected anomalous behavior')
                        
                        ev = scorer.calculate(ev)
                        if not self.deduplicator.is_duplicate(ev):
                            self.queue.add(ev)
                except Exception as e:
                    logger.error(f"Security loop error: {e}")
                    
            time.sleep(self.config.get('agent.security_interval', 10))
            
    def _queue_flush_loop(self):
        while True:
            events = self.queue.get_batch(50)
            if events:
                if self.api.send_security_events(events):
                    self.queue.clear_batch(events)
            time.sleep(5)
            
    def _blacklist_loop(self):
        self.blocked_ips = set()
        logger.info("Blacklist Sync loop started.")
        while True:
            try:
                blacklist = self.api.fetch_blacklist()
                if blacklist:
                    for ip in blacklist:
                        if ip not in self.blocked_ips:
                            logger.warning(f"ACTION REQUIRED: Blocking IP {ip}")
                            # Eksekusi blokir via fail2ban (lebih rapi), fallback ke iptables jika gagal
                            try:
                                # Coba pakai fail2ban di jail sshd
                                result = subprocess.run(['fail2ban-client', 'set', 'sshd', 'banip', ip], capture_output=True, text=True)
                                if result.returncode == 0 or "already banned" in result.stdout.lower():
                                    logger.info(f"SUCCESS: IP {ip} blocked successfully via fail2ban (sshd jail).")
                                    self.blocked_ips.add(ip)
                                    continue
                            except FileNotFoundError:
                                pass # fail2ban-client not found

                            # Fallback to iptables
                            logger.info("Falling back to iptables...")
                            try:
                                subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                logger.info(f"Rule for IP {ip} already exists in iptables. Skipping insertion.")
                                self.blocked_ips.add(ip)
                            except subprocess.CalledProcessError:
                                try:
                                    subprocess.run(['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'], check=True)
                                    logger.info(f"SUCCESS: IP {ip} blocked successfully via iptables.")
                                    self.blocked_ips.add(ip)
                                except subprocess.CalledProcessError as e:
                                    logger.error(f"FAILED to block IP {ip}: {e}")
            except Exception as e:
                logger.error(f"Blacklist loop error: {e}")
            
            # Polling setiap 30 detik
            time.sleep(30)

    def _command_loop(self):
        logger.info("Command loop started.")
        while True:
            try:
                commands = self.api.fetch_commands()
                for cmd in commands:
                    command_id = cmd.get("id")
                    action = cmd.get("action")
                    paths = cmd.get("paths", [])
                    
                    if not command_id or not action:
                        continue
                        
                    logger.info(f"Received command {action} for paths {paths}")
                    
                    if action == "scan_disk":
                        result = self.disk_manager.scan_directories(paths)
                        self.api.send_command_result(command_id, result)
                    elif action == "delete_files":
                        result = self.disk_manager.delete_paths(paths)
                        self.api.send_command_result(command_id, result)
                    elif action == "unban_ip":
                        target_ip = paths[0] if paths else None
                        unban_status = "failed"
                        if target_ip:
                            # 1. Unban from fail2ban if installed
                            try:
                                subprocess.run(['fail2ban-client', 'set', 'sshd', 'unbanip', target_ip], capture_output=True, text=True)
                            except Exception as e:
                                logger.debug(f"fail2ban unban exception: {e}")
                            # 2. Delete iptables DROP rule(s) for this IP
                            try:
                                while True:
                                    res = subprocess.run(['iptables', '-D', 'INPUT', '-s', target_ip, '-j', 'DROP'], capture_output=True)
                                    if res.returncode != 0:
                                        break
                                unban_status = "unbanned"
                                logger.info(f"SUCCESS: IP {target_ip} unbanned from iptables and fail2ban.")
                            except Exception as e:
                                logger.error(f"Error unbanning IP {target_ip} from iptables: {e}")
                            if hasattr(self, 'blocked_ips') and target_ip in self.blocked_ips:
                                self.blocked_ips.discard(target_ip)
                        self.api.send_command_result(command_id, {"status": unban_status, "ip": target_ip})
                    else:
                        logger.warning(f"Unknown command action: {action}")
                        
            except Exception as e:
                logger.error(f"Command loop error: {e}")
                
            time.sleep(15)

    def _run_test_mode(self):
        logger.info("Test mode: Generating mock security events...")
        event = {
            "event_type": "login",
            "action": "failed",
            "username": "root",
            "source_ip": "103.11.22.33",
            "severity": "high",
            "risk_score": 35
        }
        if not self.deduplicator.is_duplicate(event):
            self.queue.add(event)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--test-security', action='store_true', help='Run in test mode with mock events')
    args = parser.parse_args()
    
    agent = SikandiAgent(test_mode=args.test_security)
    agent.start()
