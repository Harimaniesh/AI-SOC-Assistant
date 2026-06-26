import csv
import json
import re
from datetime import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from backend.models import Alert
from backend.config import logger

# Regex patterns for parsing TXT log entries
FAILED_LOGIN_REGEX = re.compile(
    r"(?i)(?:failed password|login failed|authentication failed|failed login|invalid user)\s+(?:for|user)?\s*\'?([a-zA-Z0-9_\-]+)\'?\s+from\s+([\d\.]+)"
)
PORT_SCAN_REGEX = re.compile(
    r"(?i)(?:connection dropped|connection attempt|port open)\s+from\s+([\d\.]+)\s+to\s+([\d\.]+):(\d+)"
)
MALWARE_REGEX = re.compile(
    r"(?i)(?:executed|started|run|execution of|process|malicious activity)\s+(\S+\.(?:exe|bat|sh|ps1|dll|bin))"
)
PRIV_ESC_REGEX = re.compile(
    r"(?i)(?:privilege escalation|sudo|runas|administrator|admin privilege|privilege::debug|makeadmin)"
)

def parse_date(date_str: str) -> datetime:
    """Safely parse various datetime formats from logs."""
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%b %d %H:%M:%S"
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    # If all fail, return current time but log a warning
    return datetime.utcnow()

def parse_log_line_txt(line: str) -> Dict[str, Any]:
    """Parse a raw text log line using heuristics."""
    # Default values
    parsed = {
        "timestamp": datetime.utcnow(),
        "source_ip": "0.0.0.0",
        "destination_ip": "0.0.0.0",
        "event_type": "unknown",
        "details": line.strip(),
        "user": None,
        "port": None
    }
    
    # Try to extract timestamp at the beginning of the line
    # Match ISO timestamps e.g. 2026-06-27T00:38:17
    ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)", line)
    if ts_match:
        parsed["timestamp"] = parse_date(ts_match.group(1))
        line_content = line[ts_match.end():].strip()
    else:
        # Match syslog timestamp e.g. Jun 27 00:38:17
        syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
        if syslog_match:
            parsed["timestamp"] = parse_date(f"{datetime.utcnow().year} " + syslog_match.group(1))
            line_content = line[syslog_match.end():].strip()
        else:
            line_content = line.strip()

    # Apply regex matches
    # 1. Failed Login Check
    fl_match = FAILED_LOGIN_REGEX.search(line_content)
    if fl_match:
        parsed["event_type"] = "failed_login"
        parsed["user"] = fl_match.group(1)
        parsed["source_ip"] = fl_match.group(2)
        return parsed

    # 2. Port Connection Check
    ps_match = PORT_SCAN_REGEX.search(line_content)
    if ps_match:
        parsed["event_type"] = "connection_attempt"
        parsed["source_ip"] = ps_match.group(1)
        parsed["destination_ip"] = ps_match.group(2)
        parsed["port"] = int(ps_match.group(3))
        return parsed

    # 3. Malware Executable Check
    mw_match = MALWARE_REGEX.search(line_content)
    if mw_match:
        parsed["event_type"] = "process_start"
        parsed["details"] = f"Suspicious executable run: {mw_match.group(1)}"
        # Search for any IPs in the line
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line_content)
        if len(ips) >= 1:
            parsed["source_ip"] = ips[0]
        if len(ips) >= 2:
            parsed["destination_ip"] = ips[1]
        return parsed

    # 4. Privilege Escalation Check
    pe_match = PRIV_ESC_REGEX.search(line_content)
    if pe_match:
        parsed["event_type"] = "privilege_escalation"
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line_content)
        if ips:
            parsed["source_ip"] = ips[0]
        return parsed

    # Generic IP extraction fallback
    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line_content)
    if len(ips) >= 1:
        parsed["source_ip"] = ips[0]
    if len(ips) >= 2:
        parsed["destination_ip"] = ips[1]
        
    return parsed

def process_parsed_events(events: List[Dict[str, Any]], log_file_id: int, db: Session) -> int:
    """Analyze structured events and commit detected threat alerts to DB."""
    alerts_created = 0

    # Sort events by timestamp
    events = sorted(events, key=lambda x: x["timestamp"])

    # Aggregators for stateful heuristic checks
    failed_logins: Dict[str, List[datetime]] = {}  # source_ip -> list of failure timestamps
    port_scans: Dict[str, Dict[int, datetime]] = {}  # source_ip -> {port: timestamp}

    # Denylist of well-known malware/hacking tools
    malware_denylist = {"mimikatz.exe", "nc.exe", "netcat", "psexec.exe", "backdoor.sh", "keylogger.exe", "exploit.py"}

    for event in events:
        source_ip = event.get("source_ip", "0.0.0.0")
        destination_ip = event.get("destination_ip", "0.0.0.0")
        timestamp = event.get("timestamp", datetime.utcnow())
        event_type = event.get("event_type", "unknown")
        details = event.get("details", "")
        user = event.get("user")
        port = event.get("port")

        # ----------------------------------------------------
        # 1. BRUTE FORCE DETECTION (More than 10 failed logins)
        # ----------------------------------------------------
        if event_type == "failed_login" and source_ip != "0.0.0.0":
            if source_ip not in failed_logins:
                failed_logins[source_ip] = []
            failed_logins[source_ip].append(timestamp)

            # Filter logins to only include last 60 seconds
            failed_logins[source_ip] = [t for t in failed_logins[source_ip] if (timestamp - t).total_seconds() <= 60]

            if len(failed_logins[source_ip]) > 10:
                # Trigger Brute Force Alert
                # Clear to avoid double alert on subsequent failures
                failed_logins[source_ip] = []
                
                alert = Alert(
                    log_file_id=log_file_id,
                    timestamp=timestamp,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    threat_type="Brute Force",
                    severity=8,  # High
                    mitre_id="T1110",
                    status="New",
                    description=f"Brute force attempt detected: Over 10 failed logins in 60s for user '{user or 'unknown'}' from IP {source_ip}.",
                    target_system=f"User: {user or 'unknown'}",
                    raw_log_payload=details
                )
                db.add(alert)
                alerts_created += 1
                logger.info(f"Detected Threat: Brute Force from {source_ip}")

        # ----------------------------------------------------
        # 2. PORT SCAN DETECTION (Multiple unique ports)
        # ----------------------------------------------------
        if port is not None and source_ip != "0.0.0.0":
            if source_ip not in port_scans:
                port_scans[source_ip] = {}
            port_scans[source_ip][port] = timestamp

            # Keep only ports scanned in the last 60 seconds
            port_scans[source_ip] = {
                p: t for p, t in port_scans[source_ip].items() if (timestamp - t).total_seconds() <= 60
            }

            if len(port_scans[source_ip]) > 5:
                scanned_ports = list(port_scans[source_ip].keys())
                # Trigger Port Scan Alert
                # Clear to avoid duplicates
                port_scans[source_ip] = {}
                
                alert = Alert(
                    log_file_id=log_file_id,
                    timestamp=timestamp,
                    source_ip=source_ip,
                    destination_ip=destination_ip or "0.0.0.0",
                    threat_type="Port Scanning",
                    severity=5,  # Medium
                    mitre_id="T1046",
                    status="New",
                    description=f"Port scan detected: {source_ip} scanned {len(scanned_ports)} unique ports ({scanned_ports}) within 60s.",
                    target_system=f"Target: {destination_ip or 'unknown'} (Ports: {scanned_ports})",
                    raw_log_payload=details
                )
                db.add(alert)
                alerts_created += 1
                logger.info(f"Detected Threat: Port Scan from {source_ip}")

        # ----------------------------------------------------
        # 3. MALWARE DETECTION (Unknown executable or denylist)
        # ----------------------------------------------------
        if event_type == "process_start":
            # Extract executable name
            exe_match = re.search(r"(\S+\.(?:exe|bat|sh|ps1|dll|bin))", details)
            if exe_match:
                exe_name = exe_match.group(1).lower()
                is_denied = any(denied in exe_name for denied in malware_denylist)
                
                if is_denied:
                    severity = 9  # Critical
                    desc = f"Malware Execution: High-risk file run detected ({exe_name})."
                else:
                    severity = 7  # High
                    desc = f"Suspicious Execution: Execution of unknown binary ({exe_name}) in user workspace."
                    
                alert = Alert(
                    log_file_id=log_file_id,
                    timestamp=timestamp,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    threat_type="Malware Execution",
                    severity=severity,
                    mitre_id="T1204",
                    status="New",
                    description=desc,
                    target_system=f"Host Process: {exe_name}",
                    raw_log_payload=details
                )
                db.add(alert)
                alerts_created += 1
                logger.info(f"Detected Threat: Malware Execution ({exe_name})")

        # ----------------------------------------------------
        # 4. PRIVILEGE ESCALATION DETECTION (Sudo/Runas/Admin)
        # ----------------------------------------------------
        if event_type == "privilege_escalation" or PRIV_ESC_REGEX.search(details):
            alert = Alert(
                log_file_id=log_file_id,
                timestamp=timestamp,
                source_ip=source_ip,
                destination_ip=destination_ip,
                threat_type="Privilege Escalation",
                severity=9,  # Critical
                mitre_id="T1068",
                status="New",
                description=f"Privilege escalation attempt detected: Command execution or policy change requesting elevated permissions.",
                target_system="System Security Policy / Root account",
                raw_log_payload=details
            )
            db.add(alert)
            alerts_created += 1
            logger.info(f"Detected Threat: Privilege Escalation from {source_ip}")

    db.commit()
    return alerts_created

def parse_log_file(file_path: str, extension: str) -> List[Dict[str, Any]]:
    """Parse CSV, JSON, or TXT log files into structured events."""
    events = []
    
    # 1. Parse JSON Files
    if extension == ".json":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        events.append({
                            "timestamp": parse_date(str(item.get("timestamp", ""))),
                            "source_ip": str(item.get("source_ip", "0.0.0.0")),
                            "destination_ip": str(item.get("destination_ip", "0.0.0.0")),
                            "event_type": str(item.get("event_type", "unknown")),
                            "details": str(item.get("details", "")),
                            "user": item.get("user"),
                            "port": int(item.get("port")) if item.get("port") is not None else None
                        })
                else:
                    # Single object JSON
                    events.append({
                        "timestamp": parse_date(str(data.get("timestamp", ""))),
                        "source_ip": str(data.get("source_ip", "0.0.0.0")),
                        "destination_ip": str(data.get("destination_ip", "0.0.0.0")),
                        "event_type": str(data.get("event_type", "unknown")),
                        "details": str(data.get("details", "")),
                        "user": data.get("user"),
                        "port": int(data.get("port")) if data.get("port") is not None else None
                    })
        except Exception as e:
            logger.error(f"Error parsing JSON log file: {e}")
            raise ValueError(f"Invalid JSON format: {e}")

    # 2. Parse CSV Files
    elif extension == ".csv":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    events.append({
                        "timestamp": parse_date(row.get("timestamp", "")),
                        "source_ip": row.get("source_ip", "0.0.0.0"),
                        "destination_ip": row.get("destination_ip", "0.0.0.0"),
                        "event_type": row.get("event_type", "unknown"),
                        "details": row.get("details", ""),
                        "user": row.get("user") if row.get("user") else None,
                        "port": int(row.get("port")) if row.get("port") else None
                    })
        except Exception as e:
            logger.error(f"Error parsing CSV log file: {e}")
            raise ValueError(f"Invalid CSV format: {e}")

    # 3. Parse TXT Logs line-by-line
    elif extension == ".txt":
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events.append(parse_log_line_txt(line))
        except Exception as e:
            logger.error(f"Error parsing TXT log file: {e}")
            raise ValueError(f"Invalid TXT format: {e}")

    else:
        raise ValueError(f"Unsupported file extension: {extension}")

    return events
