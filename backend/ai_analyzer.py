import openai
from backend.config import settings, logger

# Fallback database of responses for offline/mock mode
FALLBACK_KNOWLEDGE = {
    "T1110": {
        "name": "Brute Force",
        "description": "Adversaries may use brute force techniques to attempt access to accounts. This involves systematically guessing passwords, API keys, or security tokens until a correct one is found. It commonly targets SSH, RDP, and web application login portals.",
        "danger": "High (Severity 8/10). A successful brute force attack leads to credential compromise, giving attackers valid user access. This allows them to bypass external firewalls, access private files, and perform lateral movement.",
        "remediation": (
            "1. **Account Lockout Policy**: Enforce lockout thresholds (e.g., lock account for 15 minutes after 5 failed attempts).\n"
            "2. **Multi-Factor Authentication (MFA)**: Require MFA for all accounts and network services.\n"
            "3. **IP Rate Limiting**: Limit connection frequencies from individual source IPs.\n"
            "4. **IP Blocking**: Temporarily or permanently block the source IP in firewall/WAF logs."
        )
    },
    "T1046": {
        "name": "Network Service Discovery (Port Scanning)",
        "description": "Adversaries may attempt to get a listing of services running on target hosts to identify vulnerabilities or open ports. This is a reconnaissance phase action, mapping the network layout and host details.",
        "danger": "Medium (Severity 5/10). Port scanning does not directly damage systems but provides attackers with a roadmap of active services, software versions, and potential entry points.",
        "remediation": (
            "1. **Strict Access Controls**: Implement firewall rules to allow only authorized traffic to public-facing systems.\n"
            "2. **Intrusion Prevention Systems (IPS)**: Deploy IPS rules to detect and automatically drop traffic from scanning hosts.\n"
            "3. **Minimize Exposed Services**: Turn off unused ports and disable service banners to prevent version finger-printing."
        )
    },
    "T1204": {
        "name": "User Execution (Malware Execution)",
        "description": "An adversary may rely on a user to execute malicious code. This could occur through phishing links/attachments or through manually executing high-risk files (e.g., hacker toolsets, scripts, remote control software).",
        "danger": "Critical (Severity 9-10/10). Execution of malicious files can lead to full system compromise, remote access trojans (RATs) installation, credential extraction, or ransomware deployment.",
        "remediation": (
            "1. **Host Isolation**: Disconnect the target machine from the network immediately to prevent lateral spread.\n"
            "2. **Terminate & Quarantines**: Terminate the malicious process and move the executable file to secure quarantine.\n"
            "3. **Credential Rotation**: Change all credentials associated with the affected host/user.\n"
            "4. **EDR/AV Scan**: Run a full Endpoint Detection and Response (EDR) scan."
        )
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities or system configuration weaknesses to gain elevated access (e.g., from local user to SYSTEM, root, or Administrator). This bypasses standard user permission gates.",
        "danger": "Critical (Severity 9-10/10). Successful privilege escalation grants the adversary administrative capabilities, allowing them to disable security tools, access kernel-level space, and install persistent rootkits.",
        "remediation": (
            "1. **Revoke Sessions**: Immediately kill the compromised user's active shell or session.\n"
            "2. **Patch Management**: Apply security updates for the operating system and running services.\n"
            "3. **Principle of Least Privilege**: Verify local administrators list and ensure regular users do not have access to admin-level privilege commands (e.g., restrict sudo permissions)."
        )
    }
}

def analyze_threat_ai(alert_type: str, mitre_id: str, source_ip: str, target: str, payload: str) -> str:
    """Use OpenAI to summarize a detected threat, or fallback to rules if key is missing."""
    if not settings.OPENAI_API_KEY:
        logger.info("OpenAI API Key not set. Using local rule-based explanation engine.")
        # Fallback heuristic generator
        mitre_info = FALLBACK_KNOWLEDGE.get(mitre_id, {})
        mitre_desc = mitre_info.get("description", "Unknown MITRE technique.")
        mitre_remed = mitre_info.get("remediation", "Please follow general incident response playbook procedures.")
        
        response = (
            f"### Incident Threat Analysis (Local Engine)\n"
            f"**Attack Type**: {alert_type}\n"
            f"**MITRE ATT&CK Mapping**: {mitre_id} ({mitre_info.get('name', 'N/A')})\n\n"
            f"#### Summary\n"
            f"We detected a suspicious event from source IP `{source_ip}` targeting `{target}`. "
            f"{mitre_desc}\n\n"
            f"#### Risk and Danger Assessment\n"
            f"{mitre_info.get('danger', 'Moderate risk level. Investigate source activity.')}\n\n"
            f"#### Raw Event Trigger Context\n"
            f"`{payload}`\n\n"
            f"#### Recommended Remediation Steps\n"
            f"{mitre_remed}"
        )
        return response

    try:
        client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
        
        prompt = (
            f"You are a professional Tier-3 SOC analyst. Analyze the following alert:\n"
            f"Threat Type: {alert_type}\n"
            f"MITRE ID: {mitre_id}\n"
            f"Source IP: {source_ip}\n"
            f"Target System/User: {target}\n"
            f"Raw Log Data: {payload}\n\n"
            f"Please write a concise explanation in markdown format including:\n"
            f"1. Threat Summary: What happened in simple SOC analyst terms.\n"
            f"2. Severity & Danger Level: How dangerous is this attack.\n"
            f"3. Remediation Checklist: Bullet points showing how the analyst should immediately remediate this issue."
        )

        response = client.chat.completions.create(
            model="gpt-4o",  # Defaulting to gpt-4o or similar available model
            messages=[
                {"role": "system", "content": "You are a professional, direct security analyst assistant who responds in simple, clear SOC language."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"OpenAI API call failed: {e}. Falling back to local engine.")
        # Return fallback if API call fails
        return analyze_threat_ai(alert_type, mitre_id, source_ip, target, payload)

def ask_chatbot_ai(user_question: str, context_alert: dict = None) -> str:
    """Answer analyst questions about security alerts and techniques."""
    # Context summary block if an alert is specified
    context_str = ""
    if context_alert:
        context_str = (
            f"Current Alert Context:\n"
            f"- Alert ID: {context_alert.get('id')}\n"
            f"- Threat Type: {context_alert.get('threat_type')}\n"
            f"- MITRE ID: {context_alert.get('mitre_id')}\n"
            f"- Source IP: {context_alert.get('source_ip')}\n"
            f"- Target: {context_alert.get('target_system')}\n"
            f"- Severity: {context_alert.get('severity')}/10\n"
            f"- Description: {context_alert.get('description')}\n"
        )

    if not settings.OPENAI_API_KEY:
        # Fallback local chatbot response parsing
        user_question_lower = user_question.lower()
        
        # Check if asking about MITRE techniques
        for mitre_id, info in FALLBACK_KNOWLEDGE.items():
            if mitre_id.lower() in user_question_lower or info["name"].lower() in user_question_lower:
                return (
                    f"### MITRE ATT&CK Info: {mitre_id} ({info['name']})\n\n"
                    f"**Technique Details**:\n{info['description']}\n\n"
                    f"**Risk Level**:\n{info['danger']}\n\n"
                    f"**Remediation Action**:\n{info['remediation']}"
                )

        if "remediate" in user_question_lower or "fix" in user_question_lower or "how to respond" in user_question_lower:
            if context_alert and context_alert.get("mitre_id") in FALLBACK_KNOWLEDGE:
                info = FALLBACK_KNOWLEDGE[context_alert["mitre_id"]]
                return f"### Remediation steps for alert {context_alert['threat_type']}:\n\n{info['remediation']}"
            return (
                "### General Incident Response Guidelines:\n\n"
                "1. **Isolate**: Unplug the network interface of affected servers to contain the threat.\n"
                "2. **Preserve**: Capture memory state or logs before removing files for forensic analysis.\n"
                "3. **Remediate**: Remove malicious lines, patch application vulnerabilities, or update configs.\n"
                "4. **Restore**: Restore from known-clean backups and reset all compromised credentials."
            )

        if "danger" in user_question_lower or "how dangerous" in user_question_lower or "severity" in user_question_lower:
            if context_alert and context_alert.get("mitre_id") in FALLBACK_KNOWLEDGE:
                info = FALLBACK_KNOWLEDGE[context_alert["mitre_id"]]
                return f"### Danger Assessment:\n\n{info['danger']}"
            return "This depends on the system context. High/Critical severity alerts indicate active exploits (like malware or root privilege abuse) and require immediate containment. Low/Medium alerts indicate scanning or initial access attempts."

        # General greeting or other questions
        return (
            "Hello! I am your AI SOC Assistant. You can ask me questions about specific alerts, "
            "MITRE techniques (e.g. T1110, T1046), danger ratings, or containment steps. "
            "(Note: Currently running in Local Offline Mode. Set `OPENAI_API_KEY` to enable GPT-4o analysis)."
        )

    try:
        client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
        messages = [
            {"role": "system", "content": "You are a professional Tier-3 SOC analyst assistant. Respond clearly and concisely to other security analysts. Use formatting like bullet points and bold text where helpful."},
        ]
        if context_str:
            messages.append({"role": "system", "content": context_str})
            
        messages.append({"role": "user", "content": user_question})

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            temperature=0.4
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"OpenAI Chatbot API call failed: {e}")
        return f"Error communicating with OpenAI API: {e}. Please contact system administrator."
