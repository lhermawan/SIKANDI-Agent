class RiskScorer:
    def __init__(self):
        self.scores = {
            # Raw events
            'login_failed': 10,
            'brute_force_detected': 50,
            'suspicious_process_started': 25,
            'file_integrity_modified': 40,
            'file_integrity_deleted': 40,
            'network_suspicious_connection': 25,
            'persistence_created': 50,
            'privilege_escalation_attempt': 40,
            'suspicious_login_detected': 20,
            # Correlation engine outputs (event_type=correlation, action=<type>)
            'correlation_brute_force': 75,
            'correlation_password_spraying': 75,
            'correlation_failed_then_success': 80,
            'correlation_new_user_privilege_escalation': 95,
            'correlation_network_scan_then_login_attack': 95,
            'correlation_persistence_then_suspicious_activity': 95,
            # Legacy
            'correlation_privilege_escalation_after_suspicious_login': 80,
        }
        
    def calculate(self, event):
        key = f"{event.get('event_type')}_{event.get('action')}"
        # For correlation events, use the risk_score already set by engine
        # but only if it's higher than the table score.
        table_score = self.scores.get(key, 5)
        existing = event.get('risk_score', 0)
        score = max(table_score, existing)
        
        # clamp
        score = min(100, max(0, score))
        
        event['risk_score'] = score
        return event

