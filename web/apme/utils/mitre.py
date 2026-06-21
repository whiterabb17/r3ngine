"""
APME MITRE ATT&CK Utility

Canonical lookup from technique ID → (name, tactic_slug, tactic_display).
Used by the pathfinder to annotate PathStep objects and by the serializer
to include MITRE attribution in API output.
"""

TECHNIQUE_CATALOG: dict[str, tuple[str, str, str]] = {
    "T1190":     ("Exploit Public-Facing Application",     "initial-access",       "Initial Access"),
    "T1059":     ("Command and Scripting Interpreter",     "execution",            "Execution"),
    "T1059.004": ("Unix Shell",                            "execution",            "Execution"),
    "T1059.006": ("Python",                                "execution",            "Execution"),
    "T1059.007": ("JavaScript",                            "execution",            "Execution"),
    "T1078":     ("Valid Accounts",                        "initial-access",       "Initial Access"),
    "T1078.001": ("Default Accounts",                      "privilege-escalation", "Privilege Escalation"),
    "T1078.004": ("Cloud Accounts",                        "defense-evasion",      "Defense Evasion"),
    "T1083":     ("File and Directory Discovery",          "discovery",            "Discovery"),
    "T1090":     ("Proxy",                                 "command-and-control",  "Command & Control"),
    "T1046":     ("Network Service Discovery",             "discovery",            "Discovery"),
    "T1021":     ("Remote Services",                       "lateral-movement",     "Lateral Movement"),
    "T1021.004": ("SSH",                                   "lateral-movement",     "Lateral Movement"),
    "T1548":     ("Abuse Elevation Control Mechanism",     "privilege-escalation", "Privilege Escalation"),
    "T1552":     ("Unsecured Credentials",                 "credential-access",    "Credential Access"),
    "T1552.001": ("Credentials In Files",                  "credential-access",    "Credential Access"),
    "T1552.005": ("Cloud Instance Metadata API",           "credential-access",    "Credential Access"),
    "T1528":     ("Steal Application Access Token",        "credential-access",    "Credential Access"),
    "T1530":     ("Data from Cloud Storage",               "collection",           "Collection"),
    "T1539":     ("Steal Web Session Cookie",              "credential-access",    "Credential Access"),
    "T1557":     ("Adversary-in-the-Middle",               "collection",           "Collection"),
    "T1557.001": ("LLMNR/NBT-NS Poisoning and Relay",      "collection",           "Collection"),
    "T1563":     ("Remote Service Session Hijacking",      "lateral-movement",     "Lateral Movement"),
    "T1566.001": ("Spearphishing Attachment",              "initial-access",       "Initial Access"),
    "T1566.002": ("Spearphishing Link",                    "initial-access",       "Initial Access"),
    "T1584.001": ("Domains",                               "resource-development", "Resource Development"),
    "T1586.002": ("Email Accounts",                        "resource-development", "Resource Development"),
    "T1185":     ("Browser Session Hijacking",             "collection",           "Collection"),
    "T1189":     ("Drive-by Compromise",                   "initial-access",       "Initial Access"),
    "T1195":     ("Supply Chain Compromise",               "initial-access",       "Initial Access"),
    "T1204.001": ("Malicious Link",                        "execution",            "Execution"),
    "T1505":     ("Server Software Component",             "persistence",          "Persistence"),
    "T1505.003": ("Web Shell",                             "persistence",          "Persistence"),
    "T1562.001": ("Disable or Modify Tools",               "defense-evasion",      "Defense Evasion"),
    "T1592":     ("Gather Victim Host Information",        "reconnaissance",       "Reconnaissance"),
}

TACTIC_COLOR: dict[str, str] = {
    "initial-access":       "#ff4444",
    "execution":            "#ff8800",
    "persistence":          "#ffcc00",
    "privilege-escalation": "#aa00ff",
    "defense-evasion":      "#0088ff",
    "credential-access":    "#00aaff",
    "discovery":            "#00ff88",
    "lateral-movement":     "#ff00aa",
    "collection":           "#ff6600",
    "command-and-control":  "#9944ff",
    "exfiltration":         "#ff0066",
    "impact":               "#ff0000",
    "resource-development": "#888888",
    "reconnaissance":       "#44aaff",
}


def lookup(technique_id: str) -> dict[str, str]:
    """Return full MITRE metadata for a technique ID.

    Returns a safe dict with all keys present even for unknown IDs,
    so callers never need to guard against KeyError.
    Unknown IDs (including None, empty string, or unrecognized codes)
    return a sentinel dict with tactic_slug='unknown'.
    """
    if not technique_id:
        return {
            "technique_id":   "",
            "technique_name": "Unknown",
            "tactic_slug":    "unknown",
            "tactic_display": "Unknown",
            "tactic_color":   "#888888",
        }
    entry = TECHNIQUE_CATALOG.get(technique_id)
    if entry is None:
        return {
            "technique_id":   technique_id,
            "technique_name": technique_id,
            "tactic_slug":    "unknown",
            "tactic_display": "Unknown",
            "tactic_color":   "#888888",
        }
    name, tactic_slug, tactic_display = entry
    return {
        "technique_id":   technique_id,
        "technique_name": name,
        "tactic_slug":    tactic_slug,
        "tactic_display": tactic_display,
        "tactic_color":   TACTIC_COLOR.get(tactic_slug, "#888888"),
    }
