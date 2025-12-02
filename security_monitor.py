#!/usr/bin/env python3
"""
Security Monitor for Linux Servers
Monitors network connections, detects attacks, blocks suspicious IPs,
and sends Telegram notifications.

IMPORTANT: This script differentiates between:
- SSH attacks (strict blocking - only whitelisted IPs allowed)
- HTTP/HTTPS traffic (soft monitoring - only blocks DDoS attacks)

Author: Vigil.sh
Version: 2.1.0
"""

import subprocess
import json
import time
import re
import os
import sys
import logging
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Set, Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

# Setup logging before any imports that might use it
logging.getLogger().handlers.clear()

try:
    import requests
except ImportError:
    print("Installing requests library...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests


@dataclass
class ThreatInfo:
    """Information about detected threat"""
    ip: str
    threat_type: str
    details: str
    timestamp: datetime
    severity: str  # low, medium, high, critical
    should_block: bool = True  # Whether to auto-block this threat
    country: str = ""  # GeoIP country
    abuse_score: int = -1  # AbuseIPDB score (-1 = not checked)


class GeoIP:
    """GeoIP lookup using free ip-api.com"""

    _cache: Dict[str, str] = {}

    @classmethod
    def get_country(cls, ip: str) -> str:
        """Get country for IP address"""
        if ip in cls._cache:
            return cls._cache[ip]

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=country,countryCode",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                country = data.get("country", "Unknown")
                code = data.get("countryCode", "")
                result = f"{country} ({code})" if code else country
                cls._cache[ip] = result
                return result
        except Exception:
            pass

        cls._cache[ip] = "Unknown"
        return "Unknown"


class AbuseIPDB:
    """Check IP reputation via AbuseIPDB API"""

    _cache: Dict[str, dict] = {}

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.enabled = bool(api_key) and api_key != "YOUR_ABUSEIPDB_KEY"

    def check_ip(self, ip: str) -> dict:
        """Check IP reputation. Returns {'score': 0-100, 'reports': N}"""
        if not self.enabled:
            return {"score": -1, "reports": 0}

        if ip in self._cache:
            return self._cache[ip]

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json().get("data", {})
                result = {
                    "score": data.get("abuseConfidenceScore", 0),
                    "reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "")
                }
                self._cache[ip] = result
                return result
        except Exception:
            pass

        return {"score": -1, "reports": 0}


class TelegramNotifier:
    """Send notifications to Telegram with rate limiting"""

    # Moscow timezone (UTC+3)
    MOSCOW_TZ = timezone(timedelta(hours=3))

    def __init__(self, bot_token: str, chat_id: str, blocked_ips_ref: set = None,
                 rate_limit_seconds: int = 60, rate_limit_max: int = 5, translate_func = None,
                 server_name: str = "", server_ip: str = ""):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{bot_token}"
        self.enabled = bot_token != "YOUR_BOT_TOKEN_HERE" and chat_id != "YOUR_CHAT_ID_HERE"
        self.blocked_ips_ref = blocked_ips_ref
        self.t = translate_func if translate_func else lambda x: x
        self.server_name = server_name
        self.server_ip = server_ip

        # Rate limiting
        self.rate_limit_seconds = rate_limit_seconds
        self.rate_limit_max = rate_limit_max
        self._sent_times: List[datetime] = []
        self._suppressed_count = 0
        self._lock = threading.Lock()

    def _check_rate_limit(self) -> bool:
        """Check if we can send message (rate limiting)"""
        with self._lock:
            now = datetime.now()
            cutoff = now - timedelta(seconds=self.rate_limit_seconds)

            # Remove old entries
            self._sent_times = [t for t in self._sent_times if t > cutoff]

            if len(self._sent_times) >= self.rate_limit_max:
                self._suppressed_count += 1
                return False

            self._sent_times.append(now)
            return True

    def get_suppressed_count(self) -> int:
        """Get and reset suppressed messages count"""
        with self._lock:
            count = self._suppressed_count
            self._suppressed_count = 0
            return count

    def send_message(self, message: str, parse_mode: str = "HTML", force: bool = False) -> bool:
        """Send message to Telegram"""
        if not self.enabled:
            logging.warning("Telegram not configured, skipping notification")
            return False

        if not force and not self._check_rate_limit():
            logging.warning("Rate limit exceeded, message suppressed")
            return False

        try:
            response = requests.post(
                f"{self.api_url}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": parse_mode
                },
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logging.error(f"Failed to send Telegram message: {e}")
            return False

    def send_alert(self, threat: ThreatInfo, was_blocked: bool) -> bool:
        """Send formatted alert with GeoIP and AbuseIPDB info"""
        severity_emoji = {
            "low": "🟡",
            "medium": "🟠",
            "high": "🔴",
            "critical": "🚨"
        }

        emoji = severity_emoji.get(threat.severity, "⚠️")
        action_text = self.t("ip_blocked") if was_blocked else self.t("monitoring_only")
        moscow_time = datetime.now(self.MOSCOW_TZ)
        blocked_count = len(self.blocked_ips_ref) if self.blocked_ips_ref else 0

        # Build country line
        country_line = f"\n<b>{self.t('country')}:</b> {threat.country}" if threat.country else ""

        # Build abuse score line
        abuse_line = ""
        if threat.abuse_score >= 0:
            abuse_emoji = "🟢" if threat.abuse_score < 25 else "🟡" if threat.abuse_score < 50 else "🔴"
            abuse_line = f"\n<b>AbuseIPDB:</b> {abuse_emoji} {threat.abuse_score}% risk"

        # Server info lines (name and IP on separate lines)
        server_info = f"🖥 <b>{self.t('server')}:</b> {self.server_name}"
        if self.server_ip and self.server_ip != "Unknown":
            server_info += f"\n🌐 <b>IP:</b> <code>{self.server_ip}</code>"

        message = f"""{emoji} <b>{self.t('security_alert').upper()}</b>
{server_info}

<b>{self.t('type')}:</b> {threat.threat_type}
<b>{self.t('severity')}:</b> {threat.severity.upper()}
<b>IP:</b> <code>{threat.ip}</code>{country_line}{abuse_line}
<b>{self.t('time')}:</b> {moscow_time.strftime('%H:%M:%S')} (MSK)

<b>{self.t('details')}:</b>
{threat.details}

<b>{self.t('action')}:</b> {action_text}
<b>{self.t('total_blocked')}:</b> {blocked_count} {self.t('ips')}"""
        return self.send_message(message)


class SecurityMonitor:
    """Main security monitoring class"""

    # Moscow timezone
    MOSCOW_TZ = timezone(timedelta(hours=3))

    # Translations
    TRANSLATIONS = {
        "ru": {
            "security_alert": "ТРЕВОГА БЕЗОПАСНОСТИ",
            "type": "Тип",
            "severity": "Серьёзность",
            "country": "Страна",
            "time": "Время",
            "details": "Детали",
            "action": "Действие",
            "total_blocked": "Всего заблокировано",
            "ip_blocked": "IP заблокирован",
            "monitoring_only": "Только мониторинг",
            "started": "Монитор безопасности запущен",
            "server": "Сервер",
            "ssh_whitelist": "SSH Whitelist",
            "blocked": "Заблокировано",
            "check_interval": "Интервал проверки",
            "protection": "Защита",
            "features": "Возможности",
            "ssh_brute_force": "SSH брутфорс",
            "unknown_ssh": "Неизвестный SSH",
            "syn_flood": "SYN Flood",
            "port_scan": "Сканирование портов",
            "http_traffic": "HTTP трафик",
            "block": "Блокировка",
            "monitor": "Мониторинг",
            "monitor_only": "Только мониторинг",
            "ips": "IP-адресов"
        },
        "en": {
            "security_alert": "SECURITY ALERT",
            "type": "Type",
            "severity": "Severity",
            "country": "Country",
            "time": "Time",
            "details": "Details",
            "action": "Action",
            "total_blocked": "Total blocked",
            "ip_blocked": "IP has been blocked",
            "monitoring_only": "Monitoring only",
            "started": "Security Monitor Started",
            "server": "Server",
            "ssh_whitelist": "SSH Whitelist",
            "blocked": "Blocked",
            "check_interval": "Check interval",
            "protection": "Protection",
            "features": "Features",
            "ssh_brute_force": "SSH Brute Force",
            "unknown_ssh": "Unknown SSH",
            "syn_flood": "SYN Flood",
            "port_scan": "Port Scan",
            "http_traffic": "HTTP Traffic",
            "block": "Block",
            "monitor": "Monitor",
            "monitor_only": "Monitor only",
            "ips": "IPs"
        }
    }

    def __init__(self, config_path: str = "config.json"):
        # Setup logging FIRST
        self.logger = logging.getLogger("security_monitor")
        self.logger.handlers.clear()
        self.logger.propagate = False

        self.config = self._load_config(config_path)

        # Set language
        self.language = self.config.get("language", "en")
        if self.language not in self.TRANSLATIONS:
            self.language = "en"

        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # Only use StreamHandler - systemd redirects stdout to log file
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)

        # Separate whitelists for different purposes
        self.ssh_whitelist: Set[str] = set(self.config.get("ssh_whitelist", []))
        self.service_whitelist: Set[str] = set(self.config.get("service_whitelist", []))

        # Legacy support: if old "whitelist" exists, add to ssh_whitelist
        if "whitelist" in self.config:
            self.ssh_whitelist.update(self.config.get("whitelist", []))

        # Always whitelist localhost
        self.service_whitelist.add("127.0.0.1")
        self.service_whitelist.add("localhost")

        self.blocked_ips: Set[str] = set()
        self.failed_ssh_attempts: Dict[str, int] = defaultdict(int)

        # Protection settings
        self.protection = self.config.get("protection", {})

        # Load previously blocked IPs from file AND iptables
        self._load_blocked_ips()

        # Setup AbuseIPDB
        self.abuseipdb = AbuseIPDB(self.config.get("abuseipdb_api_key", ""))

        # Daily stats
        self.daily_stats = {
            "threats_detected": 0,
            "ips_blocked": 0,
            "by_type": defaultdict(int),
            "by_country": defaultdict(int),
            "last_reset": datetime.now(self.MOSCOW_TZ).date()
        }

        # Port scan detection
        self._port_scan_tracker: Dict[str, Set[int]] = defaultdict(set)
        self._port_scan_times: Dict[str, datetime] = {}

        # Setup Telegram (after loading blocked IPs so we can pass the reference)
        # Note: server_name and server_ip will be set after initialization
        tg_config = self.config.get("telegram", {})
        rate_limit = self.config.get("rate_limit", {})

        # Get server info
        self.server_name = self.config.get("server_name", "") or self.run_command('hostname').strip()
        self.server_ip = self._get_server_ip()

        # Create TelegramNotifier with server info
        self.telegram = TelegramNotifier(
            tg_config.get("bot_token", ""),
            tg_config.get("chat_id", ""),
            self.blocked_ips,
            rate_limit.get("seconds", 60),
            rate_limit.get("max_messages", 5),
            self.t,
            self.server_name,
            self.server_ip
        )

        self.logger.info("Security Monitor v2.1 initialized")
        self.logger.info(f"Server: {self.server_name} ({self.server_ip})")
        self.logger.info(f"SSH Whitelist (admin IPs): {self.ssh_whitelist}")
        self.logger.info(f"Service Whitelist (internal): {self.service_whitelist}")
        self.logger.info(f"AbuseIPDB: {'enabled' if self.abuseipdb.enabled else 'disabled'}")

    def _get_server_ip(self) -> str:
        """Get server's public IP address"""
        try:
            # Try to get public IP from multiple sources
            sources = [
                "curl -s ifconfig.me",
                "curl -s icanhazip.com",
                "curl -s api.ipify.org"
            ]
            for cmd in sources:
                result = self.run_command(cmd).strip()
                if result and len(result) < 50:  # Sanity check
                    return result
        except Exception:
            pass
        return "Unknown"

    def t(self, key: str) -> str:
        """Get translation for key"""
        return self.TRANSLATIONS[self.language].get(key, key)

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.error(f"Config file not found: {config_path}")
            return {}
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in config: {e}")
            return {}

    def _load_blocked_ips(self):
        """Load previously blocked IPs from file AND from iptables"""
        # Load from file
        blocked_file = self.config.get("blocked_ips_file", "/var/log/blocked-ips.log")
        try:
            if os.path.exists(blocked_file):
                with open(blocked_file, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip:
                            self.blocked_ips.add(ip)
        except Exception as e:
            self.logger.error(f"Failed to load blocked IPs from file: {e}")

        # Also load from iptables (in case file is out of sync)
        try:
            # Use iptables-save for more reliable parsing
            output = self.run_command("iptables-save 2>/dev/null | grep '\\-A INPUT.*DROP' | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'")
            for line in output.strip().split('\n'):
                ip = line.strip()
                if ip and ip != '0.0.0.0':
                    self.blocked_ips.add(ip)
        except Exception as e:
            self.logger.error(f"Failed to load blocked IPs from iptables: {e}")

        self.logger.info(f"Loaded {len(self.blocked_ips)} previously blocked IPs")

    def _save_blocked_ip(self, ip: str):
        """Save blocked IP to file"""
        blocked_file = self.config.get("blocked_ips_file", "/var/log/blocked-ips.log")
        try:
            with open(blocked_file, 'a') as f:
                f.write(f"{ip}\n")
        except Exception as e:
            self.logger.error(f"Failed to save blocked IP: {e}")

    def run_command(self, command: str) -> str:
        """Execute shell command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            if hasattr(self, 'logger'):
                self.logger.error(f"Command timed out: {command}")
            return ""
        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.error(f"Command failed: {command}, Error: {e}")
            return ""

    def _is_ssh_whitelisted(self, ip: str) -> bool:
        """Check if IP is allowed for SSH access"""
        return ip in self.ssh_whitelist or ip in self.service_whitelist

    def _is_service_ip(self, ip: str) -> bool:
        """Check if IP is internal service (MongoDB, etc)"""
        return ip in self.service_whitelist

    def get_ssh_connections(self) -> List[Dict]:
        """Get established SSH connections"""
        output = self.run_command("netstat -tnp 2>/dev/null | grep ':22' | grep ESTABLISHED")
        connections = []

        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                foreign_addr = parts[4]
                ip = foreign_addr.rsplit(':', 1)[0]
                ip = ip.replace('[', '').replace(']', '')
                if ip:
                    connections.append({
                        "ip": ip,
                        "foreign_addr": foreign_addr,
                        "state": parts[5] if len(parts) > 5 else "UNKNOWN"
                    })

        return connections

    def check_syn_flood(self) -> List[ThreatInfo]:
        """
        Check for SYN flood attack.
        This IS blocked because it's a DDoS attack, not normal user traffic.
        """
        if not self.protection.get("block_syn_flood", True):
            return []

        threats = []
        output = self.run_command("netstat -an | grep SYN_RECV")

        syn_recv_count = len([l for l in output.strip().split('\n') if l])
        threshold = self.config.get("thresholds", {}).get("syn_recv_max", 50)
        per_ip_min = self.config.get("thresholds", {}).get("syn_recv_per_ip_min", 15)

        if syn_recv_count > threshold:
            # Group by IP
            ip_counts = defaultdict(int)
            for line in output.strip().split('\n'):
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    foreign_addr = parts[4]
                    ip = foreign_addr.rsplit(':', 1)[0]
                    ip = ip.replace('[', '').replace(']', '')
                    if ip and not self._is_service_ip(ip):
                        ip_counts[ip] += 1

            # Only block IPs with many SYN_RECV (real attack, not normal users)
            for ip, count in ip_counts.items():
                if count >= per_ip_min:
                    threats.append(ThreatInfo(
                        ip=ip,
                        threat_type="SYN Flood Attack",
                        details=f"Detected {count} half-open connections (SYN_RECV) from this IP.\nTotal SYN_RECV on server: {syn_recv_count}\nThis is a DDoS attack pattern, not normal user traffic.",
                        timestamp=datetime.now(),
                        severity="critical" if count > 50 else "high",
                        should_block=True  # Always block SYN flood
                    ))

        return threats

    def check_ssh_bruteforce(self) -> List[ThreatInfo]:
        """
        Check for SSH brute force attempts.
        This IS blocked - SSH should only be accessed by whitelisted IPs.
        Only reports NEW threats (not already blocked IPs).
        """
        if not self.protection.get("block_ssh_bruteforce", True):
            return []

        threats = []

        # Only check recent entries (last 10 minutes) to avoid re-alerting on old attacks
        output = self.run_command(
            "grep 'Failed password' /var/log/auth.log 2>/dev/null | "
            "tail -500 | "  # Only last 500 lines
            "awk '{print $(NF-3)}' | sort | uniq -c | sort -rn"
        )

        threshold = self.config.get("thresholds", {}).get("failed_ssh_max", 5)

        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 2:
                try:
                    count = int(parts[0])
                    ip = parts[1]

                    # Skip whitelisted IPs
                    if self._is_ssh_whitelisted(ip):
                        continue

                    # Skip already blocked IPs - don't re-alert!
                    if ip in self.blocked_ips:
                        continue

                    if count >= threshold:
                        # Check if this is a recent attempt (not old log entry)
                        recent_check = self.run_command(
                            f"grep 'Failed password' /var/log/auth.log 2>/dev/null | "
                            f"grep '{ip}' | tail -1"
                        )

                        if recent_check:
                            threats.append(ThreatInfo(
                                ip=ip,
                                threat_type="SSH Brute Force",
                                details=f"Detected {count} failed SSH login attempts.\nSSH access should only come from whitelisted IPs.\nThis IP is NOT in SSH whitelist.",
                                timestamp=datetime.now(),
                                severity="high" if count > 20 else "medium",
                                should_block=True  # Always block SSH bruteforce
                            ))
                except ValueError:
                    continue

        return threats

    def check_http_connections(self) -> List[ThreatInfo]:
        """
        Check HTTP/HTTPS connections.
        This is SOFT monitoring - we don't block normal users!
        Only notify, unless it's extreme.
        """
        threats = []

        # Get HTTP/HTTPS connections (ports 80, 443, 3000)
        output = self.run_command(
            "netstat -tnp 2>/dev/null | grep ESTABLISHED | "
            "grep -E ':80|:443|:3000' | "
            "grep -v '127.0.0.1' | grep -v 'localhost'"
        )

        ip_counts = defaultdict(int)
        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                foreign_addr = parts[4]
                ip = foreign_addr.rsplit(':', 1)[0]
                ip = ip.replace('[', '').replace(']', '')
                if ip and not self._is_service_ip(ip):
                    ip_counts[ip] += 1

        threshold = self.config.get("thresholds", {}).get("http_connections_per_ip_max", 100)
        should_block = self.protection.get("block_excessive_http", False)
        should_notify = self.protection.get("notify_excessive_http", True)

        for ip, count in ip_counts.items():
            if count > threshold:
                if should_notify:
                    threats.append(ThreatInfo(
                        ip=ip,
                        threat_type="High HTTP Traffic",
                        details=f"IP has {count} HTTP/HTTPS connections (threshold: {threshold}).\nThis might be a busy user or crawler.\nNOT automatically blocked unless extreme.",
                        timestamp=datetime.now(),
                        severity="low" if count < 200 else "medium",
                        should_block=should_block  # Usually False - don't block users!
                    ))

        return threats

    def check_unknown_ssh_sessions(self) -> List[ThreatInfo]:
        """
        Check for SSH sessions from non-whitelisted IPs.
        This IS blocked - only whitelisted IPs should have SSH access.
        """
        if not self.protection.get("block_unknown_ssh", True):
            return []

        threats = []
        ssh_connections = self.get_ssh_connections()

        for conn in ssh_connections:
            ip = conn["ip"]

            # Skip if already blocked or whitelisted
            if ip in self.blocked_ips:
                continue
            if self._is_ssh_whitelisted(ip):
                continue

            # Check auth log for this IP
            auth_check = self.run_command(
                f"grep '{ip}' /var/log/auth.log 2>/dev/null | tail -5"
            )

            if "Accepted" in auth_check:
                # Someone logged in from unknown IP - CRITICAL!
                threats.append(ThreatInfo(
                    ip=ip,
                    threat_type="Unknown SSH Session",
                    details=f"CRITICAL: Active SSH session from IP not in whitelist!\nLast auth log:\n{auth_check[:500]}",
                    timestamp=datetime.now(),
                    severity="critical",
                    should_block=True
                ))
            elif "Failed password" in auth_check:
                # Active brute force attempt
                threats.append(ThreatInfo(
                    ip=ip,
                    threat_type="Active SSH Brute Force",
                    details=f"IP is currently attempting SSH brute force.\nConnection state: {conn['state']}\nNot in SSH whitelist.",
                    timestamp=datetime.now(),
                    severity="high",
                    should_block=True
                ))

        return threats

    def check_port_scan(self) -> List[ThreatInfo]:
        """
        Detect port scanning attempts.
        Looks for IPs connecting to many different ports in a short time.
        """
        if not self.protection.get("detect_port_scan", True):
            return []

        threats = []
        threshold = self.config.get("thresholds", {}).get("port_scan_ports", 10)
        time_window = self.config.get("thresholds", {}).get("port_scan_seconds", 60)

        # Get all connections (including SYN_RECV, TIME_WAIT, etc)
        output = self.run_command(
            "netstat -tn 2>/dev/null | grep -v '127.0.0.1' | tail -500"
        )

        # Track ports per IP
        current_ports: Dict[str, Set[int]] = defaultdict(set)
        now = datetime.now()

        for line in output.strip().split('\n'):
            if not line or 'Local Address' in line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                try:
                    local_addr = parts[3]
                    foreign_addr = parts[4] if len(parts) > 4 else ""

                    # Extract local port
                    if ':' in local_addr:
                        port = int(local_addr.rsplit(':', 1)[1])
                        ip = foreign_addr.rsplit(':', 1)[0] if ':' in foreign_addr else ""
                        ip = ip.replace('[', '').replace(']', '')

                        if ip and not self._is_service_ip(ip) and ip not in self.blocked_ips:
                            current_ports[ip].add(port)
                except (ValueError, IndexError):
                    continue

        # Check for port scan patterns
        for ip, ports in current_ports.items():
            # Clean old tracking data
            if ip in self._port_scan_times:
                if (now - self._port_scan_times[ip]).seconds > time_window:
                    self._port_scan_tracker[ip].clear()

            # Update tracker
            self._port_scan_tracker[ip].update(ports)
            self._port_scan_times[ip] = now

            unique_ports = len(self._port_scan_tracker[ip])
            if unique_ports >= threshold:
                threats.append(ThreatInfo(
                    ip=ip,
                    threat_type="Port Scan Detected",
                    details=f"IP connected to {unique_ports} different ports.\nPorts: {sorted(self._port_scan_tracker[ip])[:20]}...\nThis is typical port scanning behavior.",
                    timestamp=datetime.now(),
                    severity="high" if unique_ports > 20 else "medium",
                    should_block=self.protection.get("block_port_scan", True)
                ))
                # Clear tracker after detection
                self._port_scan_tracker[ip].clear()

        return threats

    def enrich_threat(self, threat: ThreatInfo) -> ThreatInfo:
        """Add GeoIP and AbuseIPDB info to threat"""
        # Get country
        threat.country = GeoIP.get_country(threat.ip)

        # Check AbuseIPDB
        abuse_info = self.abuseipdb.check_ip(threat.ip)
        threat.abuse_score = abuse_info.get("score", -1)

        return threat

    def update_daily_stats(self, threat: ThreatInfo, was_blocked: bool):
        """Update daily statistics"""
        today = datetime.now(self.MOSCOW_TZ).date()

        # Reset stats if new day
        if self.daily_stats["last_reset"] != today:
            self.daily_stats = {
                "threats_detected": 0,
                "ips_blocked": 0,
                "by_type": defaultdict(int),
                "by_country": defaultdict(int),
                "last_reset": today
            }

        self.daily_stats["threats_detected"] += 1
        if was_blocked:
            self.daily_stats["ips_blocked"] += 1
        self.daily_stats["by_type"][threat.threat_type] += 1
        if threat.country:
            country = threat.country.split("(")[0].strip()
            self.daily_stats["by_country"][country] += 1

    def send_daily_report(self):
        """Send daily summary report"""
        moscow_time = datetime.now(self.MOSCOW_TZ)

        # Get top countries
        top_countries = sorted(
            self.daily_stats["by_country"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        countries_text = "\n".join(
            f"  • {country}: {count}" for country, count in top_countries
        ) if top_countries else "  Нет данных"

        # Get threat types
        types_text = "\n".join(
            f"  • {ttype}: {count}"
            for ttype, count in self.daily_stats["by_type"].items()
        ) if self.daily_stats["by_type"] else "  Нет угроз"

        # Get suppressed messages count
        suppressed = self.telegram.get_suppressed_count()
        suppressed_text = f"\n⚠️ Пропущено уведомлений (rate limit): {suppressed}" if suppressed > 0 else ""

        # Server info (name and IP on separate lines)
        server_info = f"🖥 <b>{self.t('server')}:</b> {self.server_name}"
        if self.server_ip and self.server_ip != "Unknown":
            server_info += f"\n🌐 <b>IP:</b> <code>{self.server_ip}</code>"

        message = f"""📊 <b>DAILY REPORT</b>
{server_info}
{moscow_time.strftime('%Y-%m-%d')}

<b>Статистика за сутки:</b>
• Обнаружено угроз: {self.daily_stats['threats_detected']}
• Заблокировано IP: {self.daily_stats['ips_blocked']}
• Всего в блоке: {len(self.blocked_ips)} IPs

<b>По типам:</b>
{types_text}

<b>Топ стран-атакующих:</b>
{countries_text}{suppressed_text}"""

        self.telegram.send_message(message, force=True)

    def block_ip(self, ip: str, threat_type: str) -> bool:
        """Block IP using iptables"""
        # Never block service IPs
        if self._is_service_ip(ip):
            self.logger.warning(f"Cannot block service IP: {ip}")
            return False

        # For SSH threats, check SSH whitelist
        if "SSH" in threat_type and self._is_ssh_whitelisted(ip):
            self.logger.warning(f"Cannot block SSH-whitelisted IP: {ip}")
            return False

        if ip in self.blocked_ips:
            self.logger.info(f"IP already blocked: {ip}")
            return True

        if not self.config.get("auto_block", True):
            self.logger.info(f"Auto-block disabled, would block: {ip}")
            return False

        # Check if already blocked in iptables
        check = self.run_command(f"iptables -L INPUT -n | grep '{ip}'")
        if ip in check:
            self.blocked_ips.add(ip)
            return True

        # Block the IP
        self.run_command(f"iptables -A INPUT -s {ip} -j DROP")

        # Kill existing connections
        self.run_command(f"ss -K dst {ip} 2>/dev/null")

        self.blocked_ips.add(ip)
        self._save_blocked_ip(ip)
        self.logger.info(f"Blocked IP: {ip} (reason: {threat_type})")

        return True

    def handle_threat(self, threat: ThreatInfo):
        """Handle detected threat"""
        self.logger.warning(f"Threat detected: {threat.threat_type} from {threat.ip}")

        # Enrich with GeoIP and AbuseIPDB
        threat = self.enrich_threat(threat)

        was_blocked = False
        if threat.should_block:
            was_blocked = self.block_ip(threat.ip, threat.threat_type)

        # Update daily stats
        self.update_daily_stats(threat, was_blocked)

        # Send Telegram notification
        self.telegram.send_alert(threat, was_blocked)

    def run_check(self):
        """Run all security checks"""
        self.logger.info("Running security checks...")
        all_threats = []

        # Check for SYN flood (BLOCKS - it's DDoS)
        syn_threats = self.check_syn_flood()
        all_threats.extend(syn_threats)

        # Check for SSH brute force (BLOCKS - only whitelist allowed)
        ssh_threats = self.check_ssh_bruteforce()
        all_threats.extend(ssh_threats)

        # Check for unknown SSH sessions (BLOCKS - only whitelist allowed)
        session_threats = self.check_unknown_ssh_sessions()
        all_threats.extend(session_threats)

        # Check for port scanning
        port_scan_threats = self.check_port_scan()
        all_threats.extend(port_scan_threats)

        # Check HTTP connections (NOTIFIES ONLY - don't block users!)
        http_threats = self.check_http_connections()
        all_threats.extend(http_threats)

        # Handle all threats
        for threat in all_threats:
            if threat.ip not in self.blocked_ips or not threat.should_block:
                self.handle_threat(threat)

        if not all_threats:
            self.logger.info("No threats detected")
        else:
            blocked_count = sum(1 for t in all_threats if t.should_block)
            notify_count = len(all_threats) - blocked_count
            self.logger.info(f"Processed {len(all_threats)} threats ({blocked_count} blocked, {notify_count} notify-only)")

    def run_forever(self):
        """Run monitoring loop"""
        interval = self.config.get("check_interval_seconds", 60)
        daily_report_hour = self.config.get("daily_report_hour", 9)  # 9:00 MSK by default
        self.logger.info(f"Starting monitoring loop (interval: {interval}s)")

        # Send startup notification
        block_icon = "🛡"
        monitor_icon = "👁"

        # Build protection status lines
        ssh_bf_status = f"{block_icon} {self.t('block')}" if self.protection.get('block_ssh_bruteforce', True) else f"{monitor_icon} {self.t('monitor')}"
        unknown_ssh_status = f"{block_icon} {self.t('block')}" if self.protection.get('block_unknown_ssh', True) else f"{monitor_icon} {self.t('monitor')}"
        syn_flood_status = f"{block_icon} {self.t('block')}" if self.protection.get('block_syn_flood', True) else f"{monitor_icon} {self.t('monitor')}"
        port_scan_status = f"{block_icon} {self.t('block')}" if self.protection.get('block_port_scan', True) else f"{monitor_icon} {self.t('monitor')}"
        http_status = f"{block_icon} {self.t('block')}" if self.protection.get('block_excessive_http', False) else f"{monitor_icon} {self.t('monitor_only')}"

        server_line = f"🖥 <b>{self.t('server')}:</b> {self.server_name}"
        if self.server_ip and self.server_ip != "Unknown":
            server_line += f"\n🌐 <b>IP:</b> <code>{self.server_ip}</code>"

        self.telegram.send_message(
            f"🟢 <b>{self.t('started')}</b>\n\n"
            f"{server_line}\n"
            f"{self.t('ssh_whitelist')}: {len(self.ssh_whitelist)} {self.t('ips')}\n"
            f"{self.t('blocked')}: {len(self.blocked_ips)} {self.t('ips')}\n"
            f"{self.t('check_interval')}: {interval}s\n\n"
            f"<b>{self.t('protection')}:</b>\n"
            f"• {self.t('ssh_brute_force')}: {ssh_bf_status}\n"
            f"• {self.t('unknown_ssh')}: {unknown_ssh_status}\n"
            f"• {self.t('syn_flood')}: {syn_flood_status}\n"
            f"• {self.t('port_scan')}: {port_scan_status}\n"
            f"• {self.t('http_traffic')}: {http_status}\n\n"
            f"<b>{self.t('features')}:</b>\n"
            f"• ✅ GeoIP\n"
            f"• ✅ Rate Limit",
            "HTML",
            force=True
        )

        last_report_date = None

        try:
            while True:
                self.run_check()

                # Check if it's time to send daily report
                moscow_now = datetime.now(self.MOSCOW_TZ)
                if (moscow_now.hour == daily_report_hour and
                    last_report_date != moscow_now.date()):
                    self.send_daily_report()
                    last_report_date = moscow_now.date()

                time.sleep(interval)
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
            self.telegram.send_message("🔴 <b>Security Monitor Stopped</b>", "HTML", force=True)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Security Monitor v2.1")
    parser.add_argument(
        "-c", "--config",
        default="config.json",
        help="Path to config file"
    )
    parser.add_argument(
        "--check-once",
        action="store_true",
        help="Run single check and exit"
    )
    parser.add_argument(
        "--add-ssh-whitelist",
        help="Add IP to SSH whitelist (admin access)"
    )
    parser.add_argument(
        "--add-service-whitelist",
        help="Add IP to service whitelist (internal services)"
    )
    parser.add_argument(
        "--show-status",
        action="store_true",
        help="Show current status"
    )
    parser.add_argument(
        "--send-report",
        action="store_true",
        help="Send daily report now"
    )
    parser.add_argument(
        "--check-ip",
        help="Check IP reputation (GeoIP + AbuseIPDB)"
    )

    args = parser.parse_args()

    # Find config file
    config_path = args.config
    if not os.path.exists(config_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, "config.json")

    monitor = SecurityMonitor(config_path)

    if args.add_ssh_whitelist:
        ip = args.add_ssh_whitelist
        monitor.ssh_whitelist.add(ip)
        monitor.config["ssh_whitelist"] = list(monitor.ssh_whitelist)
        with open(config_path, 'w') as f:
            json.dump(monitor.config, f, indent=2)
        print(f"Added {ip} to SSH whitelist")
        return

    if args.add_service_whitelist:
        ip = args.add_service_whitelist
        monitor.service_whitelist.add(ip)
        monitor.config["service_whitelist"] = list(monitor.service_whitelist)
        with open(config_path, 'w') as f:
            json.dump(monitor.config, f, indent=2)
        print(f"Added {ip} to service whitelist")
        return

    if args.check_ip:
        ip = args.check_ip
        print(f"Checking IP: {ip}")
        print(f"  Country: {GeoIP.get_country(ip)}")
        abuse = monitor.abuseipdb.check_ip(ip)
        if abuse["score"] >= 0:
            print(f"  AbuseIPDB: {abuse['score']}% risk ({abuse['reports']} reports)")
        else:
            print(f"  AbuseIPDB: disabled or error")
        print(f"  Blocked: {'Yes' if ip in monitor.blocked_ips else 'No'}")
        return

    if args.send_report:
        monitor.send_daily_report()
        print("Daily report sent")
        return

    if args.show_status:
        print(f"Security Monitor v2.1")
        print(f"SSH Whitelist (admin IPs): {monitor.ssh_whitelist}")
        print(f"Service Whitelist (internal): {monitor.service_whitelist}")
        print(f"Blocked IPs: {len(monitor.blocked_ips)}")
        print(f"Telegram enabled: {monitor.telegram.enabled}")
        print(f"AbuseIPDB enabled: {monitor.abuseipdb.enabled}")
        print(f"\nProtection settings:")
        for key, value in monitor.protection.items():
            status = "🛡 Block" if value else "👁 Monitor"
            print(f"  {key}: {status}")
        return

    if args.check_once:
        monitor.run_check()
    else:
        monitor.run_forever()


if __name__ == "__main__":
    main()
