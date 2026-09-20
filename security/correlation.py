from collections import defaultdict
from datetime import datetime


class CorrelationEngine:
    """
    Correlates security events into attack patterns.

    The engine does not create incidents directly.
    It groups related events and returns synthetic correlated events
    compatible with RiskScorer and the SIKANDI API.

    Output events use:
        event_type = "correlation"
        action     = <correlation_type>   ← used by RiskScorer key
    """

    def __init__(self):
        self.rules = [
            self._detect_brute_force,
            self._detect_password_spraying,
            self._detect_failed_then_success,
            self._detect_new_user_privilege,
            self._detect_network_attack,
            self._detect_persistence_chain,
        ]

    def analyze(self, events):
        if not events:
            return []

        normalized_events = [
            self._normalize_event(event)
            for event in events
            if isinstance(event, dict)
        ]

        results = []

        for rule in self.rules:
            try:
                detected = rule(normalized_events)
                if detected:
                    if isinstance(detected, list):
                        results.extend(detected)
                    else:
                        results.append(detected)
            except Exception:
                continue

        deduplicated = self._deduplicate_results(results)
        return [self._to_event(r) for r in deduplicated]

    # =========================================================
    # CONVERT TO API EVENT FORMAT
    # =========================================================

    def _to_event(self, result):
        """Convert a correlation result to a flat agent event dict."""
        return {
            "event_type": "correlation",
            "action": result.get("correlation_type", "unknown"),
            "severity": result.get("severity", "medium"),
            "risk_score": result.get("risk_score", 50),
            "reason": result.get("description", result.get("title", "")),
            "source_ip": result.get("source_ip", ""),
            "username": result.get("username", ""),
            "correlation_title": result.get("title", ""),
            "correlation_event_count": len(result.get("events", [])),
        }

    # =========================================================
    # NORMALIZATION
    # =========================================================

    def _normalize_event(self, event):
        normalized = dict(event)
        raw_type = (event.get("event_type") or event.get("type") or "unknown")
        normalized["event_type"] = raw_type.lower()
        normalized["action"] = (event.get("action") or "").lower()
        normalized["username"] = event.get("username") or ""
        normalized["source_ip"] = (event.get("source_ip") or event.get("src_ip") or "")
        normalized["hostname"] = event.get("hostname") or ""
        return normalized

    # =========================================================
    # BRUTE FORCE
    # =========================================================

    def _detect_brute_force(self, events):
        grouped = defaultdict(list)
        for event in events:
            if not self._is_login_fail(event):
                continue
            source_ip = event["source_ip"]
            if source_ip:
                grouped[source_ip].append(event)

        results = []
        for source_ip, failed_events in grouped.items():
            count = len(failed_events)
            if count < 5:
                continue
            if count >= 20:
                severity, risk_score = "critical", 90
            elif count >= 10:
                severity, risk_score = "high", 75
            else:
                severity, risk_score = "medium", 50

            results.append({
                "correlation_type": "brute_force",
                "severity": severity,
                "risk_score": risk_score,
                "title": "Brute Force Login Attack",
                "description": f"{count} failed login attempts detected from {source_ip}",
                "source_ip": source_ip,
                "events": failed_events,
            })
        return results

    # =========================================================
    # PASSWORD SPRAYING
    # =========================================================

    def _detect_password_spraying(self, events):
        grouped = defaultdict(list)
        for event in events:
            if not self._is_login_fail(event):
                continue
            source_ip = event["source_ip"]
            if source_ip:
                grouped[source_ip].append(event)

        results = []
        for source_ip, failed_events in grouped.items():
            usernames = {e["username"] for e in failed_events if e["username"]}
            if len(usernames) < 5:
                continue
            if len(usernames) >= 12:
                severity, risk_score = "critical", 90
            elif len(usernames) >= 8:
                severity, risk_score = "high", 75
            else:
                severity, risk_score = "medium", 55

            results.append({
                "correlation_type": "password_spraying",
                "severity": severity,
                "risk_score": risk_score,
                "title": "Password Spraying / Username Enumeration",
                "description": f"{len(usernames)} different usernames targeted from {source_ip}",
                "source_ip": source_ip,
                "usernames": sorted(usernames),
                "events": failed_events,
            })
        return results

    # =========================================================
    # FAILED LOGIN → SUCCESSFUL LOGIN
    # =========================================================

    def _detect_failed_then_success(self, events):
        results = []
        login_events = [e for e in events if self._is_login_event(e)]

        for success in login_events:
            if not self._is_login_success(success):
                continue
            related = []
            for failed in login_events:
                if not self._is_login_fail(failed):
                    continue
                if success["source_ip"] and failed["source_ip"] and success["source_ip"] != failed["source_ip"]:
                    continue
                if success["username"] and failed["username"] and success["username"] != failed["username"]:
                    continue
                if self._event_before(failed, success):
                    related.append(failed)

            if not related:
                continue

            results.append({
                "correlation_type": "failed_then_success",
                "severity": "high",
                "risk_score": 80,
                "title": "Successful Login After Failed Attempts",
                "description": f"Successful login for {success['username'] or 'unknown user'} after multiple failed attempts",
                "source_ip": success["source_ip"],
                "username": success["username"],
                "events": related + [success],
            })
        return results

    # =========================================================
    # NEW USER + PRIVILEGE ESCALATION
    # =========================================================

    def _detect_new_user_privilege(self, events):
        new_users = [e for e in events if e["event_type"] in ("new_user", "user_created", "account_created")]
        priv_events = [e for e in events if e["event_type"] in ("privilege_escalation", "sudo_change", "admin_group_change", "group_membership_change")]

        results = []
        for user_event in new_users:
            username = user_event["username"]
            for priv_event in priv_events:
                if priv_event["username"] and username and priv_event["username"] != username:
                    continue
                results.append({
                    "correlation_type": "new_user_privilege_escalation",
                    "severity": "critical",
                    "risk_score": 95,
                    "title": "New User With Elevated Privileges",
                    "description": f"New user {username} was associated with a privilege escalation event",
                    "username": username,
                    "events": [user_event, priv_event],
                })
        return results

    # =========================================================
    # NETWORK SCAN → LOGIN ATTACK
    # =========================================================

    def _detect_network_attack(self, events):
        network_events = [e for e in events if e["event_type"] in ("port_scan", "network_scan", "suspicious_network")]
        login_fails = [e for e in events if self._is_login_fail(e)]

        results = []
        for network in network_events:
            source_ip = network["source_ip"]
            if not source_ip:
                continue
            related_login = [e for e in login_fails if e["source_ip"] == source_ip]
            if not related_login:
                continue
            results.append({
                "correlation_type": "network_scan_then_login_attack",
                "severity": "critical",
                "risk_score": 95,
                "title": "Network Scan Followed By Login Attack",
                "description": f"Network scanning from {source_ip} followed by failed login attempts",
                "source_ip": source_ip,
                "events": [network, *related_login],
            })
        return results

    # =========================================================
    # PERSISTENCE → SUSPICIOUS ACTIVITY
    # =========================================================

    def _detect_persistence_chain(self, events):
        persistence_events = [e for e in events if e["event_type"] in ("persistence_change", "cron_change", "systemd_change", "ssh_key_change", "startup_change")]
        suspicious_events = [e for e in events if e["event_type"] in ("suspicious_process", "suspicious_network", "privilege_escalation")]

        results = []
        for persistence in persistence_events:
            related = [s for s in suspicious_events if not (persistence["username"] and s["username"] and persistence["username"] != s["username"])]
            if not related:
                continue
            results.append({
                "correlation_type": "persistence_then_suspicious_activity",
                "severity": "critical",
                "risk_score": 95,
                "title": "Persistence Change Followed By Suspicious Activity",
                "description": "A persistence mechanism was modified followed by suspicious system activity",
                "username": persistence["username"],
                "events": [persistence, *related],
            })
        return results

    # =========================================================
    # HELPERS — login classification
    # =========================================================

    def _is_login_event(self, event):
        t = event["event_type"]
        a = event["action"]
        return (
            t in ("login", "login_attempt", "authentication", "authentication_attempt",
                  "ssh_login", "failed_login", "successful_login", "loginfailed",
                  "login_failed", "brute_force")
            or "login" in t
            or a in ("failed", "success", "successful", "accepted", "denied", "login_failed")
        )

    def _is_login_fail(self, event):
        t = event["event_type"]
        a = event["action"]
        if a in ("failed", "failure", "denied", "login_failed"):
            return True
        if t in ("failed_login", "loginfailed", "login_failed"):
            return True
        if t == "brute_force" and a == "detected":
            return True
        if "login" in t and "fail" in t:
            return True
        return False

    def _is_login_success(self, event):
        if self._is_login_fail(event):
            return False
        t = event["event_type"]
        a = event["action"]
        if a in ("success", "successful", "accepted", "ok"):
            return True
        if t in ("successful_login", "loginsuccess", "login_success"):
            return True
        return False

    def _event_before(self, first, second):
        t1 = self._get_timestamp(first)
        t2 = self._get_timestamp(second)
        if t1 is None or t2 is None:
            return True
        return t1 <= t2

    def _get_timestamp(self, event):
        ts = event.get("timestamp")
        if ts is None:
            return None
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except ValueError:
                return None
        return None

    def _deduplicate_results(self, results):
        unique = []
        fingerprints = set()
        for result in results:
            event_ids = [str(e["event_id"]) for e in result.get("events", []) if e.get("event_id")]
            fingerprint = (
                result.get("correlation_type"),
                result.get("source_ip"),
                result.get("username"),
                tuple(sorted(event_ids)),
            )
            if fingerprint in fingerprints:
                continue
            fingerprints.add(fingerprint)
            unique.append(result)
        return unique

