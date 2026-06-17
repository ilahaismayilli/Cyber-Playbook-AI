INCIDENT_KEYWORDS = {
    "phishing": [
        "phishing",
        "email",
        "suspicious link",
        "credential",
        "password",
        "attachment",
        "sender",
        "invoice",
        "mfa code",
    ],
    "malware": [
        "malware",
        "virus",
        "trojan",
        "ransomware",
        "payload",
        "infected",
        "quarantine",
        "hash",
        "executable",
    ],
    "brute_force": [
        "failed login",
        "failed logins",
        "brute force",
        "password spray",
        "successful login",
        "unusual country",
        "admin account",
        "account locked",
    ],
    "data_exfiltration": [
        "exfiltration",
        "large download",
        "large upload",
        "data transfer",
        "sensitive data",
        "external destination",
        "dropbox",
        "mega",
        "google drive",
    ],
    "suspicious_powershell": [
        "powershell",
        "encodedcommand",
        "encoded command",
        "bypass",
        "downloadstring",
        "invoke-webrequest",
        "iex",
        "script",
    ],
}

HIGH_SEVERITY_KEYWORDS = [
    "admin",
    "administrator",
    "domain controller",
    "ransomware",
    "data exfiltration",
    "sensitive data",
    "successful login",
    "lateral movement",
    "credential dumping",
]

MEDIUM_SEVERITY_KEYWORDS = [
    "failed login",
    "suspicious",
    "malware",
    "powershell",
    "attachment",
    "external",
    "unusual",
]


def classify_alert(alert_text):
    text = alert_text.lower()
    scores = {}

    for incident_type, keywords in INCIDENT_KEYWORDS.items():
        scores[incident_type] = sum(1 for keyword in keywords if keyword in text)

    best_type = max(scores, key=scores.get)
    if scores[best_type] == 0:
        best_type = "unknown"

    severity = estimate_severity(text)

    return {
        "incident_type": best_type,
        "severity": severity,
        "confidence": build_confidence_label(scores.get(best_type, 0)),
        "matched_keywords": get_matched_keywords(text, best_type),
    }


def estimate_severity(text):
    high_matches = sum(1 for keyword in HIGH_SEVERITY_KEYWORDS if keyword in text)
    medium_matches = sum(1 for keyword in MEDIUM_SEVERITY_KEYWORDS if keyword in text)

    if high_matches >= 2:
        return "Critical"
    if high_matches == 1:
        return "High"
    if medium_matches >= 2:
        return "Medium"
    return "Low"


def build_confidence_label(score):
    if score >= 3:
        return "High"
    if score == 2:
        return "Medium"
    if score == 1:
        return "Low"
    return "Very Low"


def get_matched_keywords(text, incident_type):
    if incident_type not in INCIDENT_KEYWORDS:
        return []

    return [
        keyword
        for keyword in INCIDENT_KEYWORDS[incident_type]
        if keyword in text
    ]

