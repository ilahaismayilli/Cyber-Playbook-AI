PLAYBOOKS = {
    "phishing": {
        "name": "Phishing Response",
        "steps": [
            "Collect the reported email, headers, sender address, subject, links, and attachments.",
            "Check whether any user clicked links, opened attachments, or submitted credentials.",
            "Quarantine similar emails from other mailboxes.",
            "Block malicious sender domains, URLs, and attachment hashes if confirmed.",
            "Reset passwords and revoke active sessions for affected users.",
            "Document indicators of compromise and notify users if needed."
        ],
    },
    "malware": {
        "name": "Malware / Endpoint Response",
        "steps": [
            "Isolate the affected endpoint from the network.",
            "Collect hostname, username, process details, file paths, hashes, and alert timestamps.",
            "Review endpoint telemetry for suspicious parent and child processes.",
            "Run endpoint protection scan and preserve evidence before cleanup.",
            "Check for lateral movement, persistence, and credential access.",
            "Reimage or clean the host based on severity and business impact."
        ],
    },
    "brute_force": {
        "name": "Account Compromise Response",
        "steps": [
            "Lock or temporarily disable the affected account if compromise is likely.",
            "Force a password reset and revoke active sessions.",
            "Verify MFA status and check for suspicious MFA prompts or changes.",
            "Review login history, source IPs, geolocation, and device information.",
            "Check whether the account accessed sensitive systems after the suspicious login.",
            "Block malicious IP addresses when appropriate and escalate if admin access was involved."
        ],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration Response",
        "steps": [
            "Identify the user, host, application, destination, and amount of data transferred.",
            "Confirm whether the destination is approved or suspicious.",
            "Contain the source account or host if unauthorized transfer is likely.",
            "Preserve logs from network, endpoint, identity, and cloud systems.",
            "Determine what data may have been exposed.",
            "Escalate to legal, privacy, and leadership teams based on company policy."
        ],
    },
    "suspicious_powershell": {
        "name": "Suspicious PowerShell Response",
        "steps": [
            "Collect the full command line, parent process, user, host, and timestamp.",
            "Check whether the command used encoded content, download commands, or bypass flags.",
            "Review related process activity before and after execution.",
            "Isolate the host if the command appears malicious.",
            "Search for the same command or script across other endpoints.",
            "Escalate if credential dumping, persistence, or lateral movement is suspected."
        ],
    },
    "unknown": {
        "name": "General Triage Response",
        "steps": [
            "Collect alert source, affected user, affected host, timestamp, and raw event details.",
            "Validate whether the activity is expected business activity.",
            "Check related identity, endpoint, network, and cloud logs.",
            "Determine business impact and affected asset criticality.",
            "Escalate if there is evidence of compromise or sensitive data exposure.",
            "Document findings and close only after the activity is explained."
        ],
    },
}


def get_playbook(incident_type):
    return PLAYBOOKS.get(incident_type, PLAYBOOKS["unknown"])

