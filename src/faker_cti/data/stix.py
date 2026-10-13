"""Static STIX 2.1 / OpenCTI vocabulary."""

# Namespace defined by the STIX 2.1 specification for deterministic SCO identifiers.
# OpenCTI (pycti) reuses it to generate the standard_id of every entity.
STIX_NAMESPACE = "00abedb4-aa42-466c-9c01-fed23315a9b7"

# Well-known TLP marking definitions. The TLP 1.0 ids come from the STIX 2.1
# specification; TLP:CLEAR shares the TLP:WHITE id in OpenCTI and TLP:AMBER+STRICT
# is the static id hard-coded by OpenCTI.
TLP_MARKINGS: dict[str, str] = {
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# PAP markings are not hard-coded by OpenCTI: their ids derive from
# uuid5(STIX_NAMESPACE, {"definition": ..., "definition_type": "PAP"}).
PAP_MARKINGS: dict[str, str] = {
    "PAP:CLEAR": "marking-definition--4cdff7eb-acb8-543f-8573-829eb9fe8b34",
    "PAP:GREEN": "marking-definition--89484dde-e3d2-547f-a6c6-d14824429eb1",
    "PAP:AMBER": "marking-definition--a6f20d4d-0360-59b6-ba22-3b48707828b1",
    "PAP:RED": "marking-definition--4e4e3b84-de45-53df-9d9b-b21207699fd8",
}

# Extension definition used by OpenCTI for its custom SDO properties.
OPENCTI_SDO_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

STIX_DOMAIN_OBJECT_TYPES: tuple[str, ...] = (
    "attack-pattern",
    "campaign",
    "course-of-action",
    "grouping",
    "identity",
    "incident",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "location",
    "malware",
    "malware-analysis",
    "note",
    "observed-data",
    "opinion",
    "report",
    "threat-actor",
    "tool",
    "vulnerability",
)

STIX_CYBER_OBSERVABLE_TYPES: tuple[str, ...] = (
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
)

STIX_META_OBJECT_TYPES: tuple[str, ...] = (
    "marking-definition",
    "external-reference",
    "kill-chain-phase",
    "label",
)

# STIX type -> OpenCTI entity_type (as returned by the GraphQL API / enrichment messages)
OPENCTI_OBSERVABLE_ENTITY_TYPES: dict[str, str] = {
    "artifact": "Artifact",
    "autonomous-system": "Autonomous-System",
    "directory": "Directory",
    "domain-name": "Domain-Name",
    "email-addr": "Email-Addr",
    "email-message": "Email-Message",
    "file": "StixFile",
    "hostname": "Hostname",
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "mac-addr": "Mac-Addr",
    "mutex": "Mutex",
    "network-traffic": "Network-Traffic",
    "process": "Process",
    "software": "Software",
    "url": "Url",
    "user-account": "User-Account",
    "windows-registry-key": "Windows-Registry-Key",
    "x509-certificate": "X509-Certificate",
}

OPENCTI_DOMAIN_ENTITY_TYPES: dict[str, str] = {
    "attack-pattern": "Attack-Pattern",
    "campaign": "Campaign",
    "course-of-action": "Course-Of-Action",
    "grouping": "Grouping",
    "incident": "Incident",
    "indicator": "Indicator",
    "infrastructure": "Infrastructure",
    "intrusion-set": "Intrusion-Set",
    "malware": "Malware",
    "malware-analysis": "Malware-Analysis",
    "note": "Note",
    "observed-data": "Observed-Data",
    "opinion": "Opinion",
    "report": "Report",
    "threat-actor": "Threat-Actor-Group",
    "tool": "Tool",
    "vulnerability": "Vulnerability",
}

OBSERVABLE_PARENT_TYPES: tuple[str, ...] = (
    "Basic-Object",
    "Stix-Object",
    "Stix-Core-Object",
    "Stix-Cyber-Observable",
)

DOMAIN_OBJECT_PARENT_TYPES: tuple[str, ...] = (
    "Basic-Object",
    "Stix-Object",
    "Stix-Core-Object",
    "Stix-Domain-Object",
)

RELATIONSHIP_TYPES: tuple[str, ...] = (
    "attributed-to",
    "based-on",
    "belongs-to",
    "communicates-with",
    "compromises",
    "delivers",
    "drops",
    "exploits",
    "has",
    "indicates",
    "located-at",
    "originates-from",
    "related-to",
    "resolves-to",
    "targets",
    "uses",
    "variant-of",
)

REPORT_TYPES: tuple[str, ...] = (
    "threat-report",
    "attack-pattern",
    "campaign",
    "identity",
    "indicator",
    "intrusion-set",
    "malware",
    "observed-data",
    "threat-actor",
    "tool",
    "vulnerability",
    "internal-report",
)

INDICATOR_TYPES: tuple[str, ...] = (
    "anomalous-activity",
    "anonymization",
    "attribution",
    "benign",
    "compromised",
    "malicious-activity",
    "unknown",
)

MALWARE_TYPES: tuple[str, ...] = (
    "adware",
    "backdoor",
    "bot",
    "bootkit",
    "ddos",
    "downloader",
    "dropper",
    "exploit-kit",
    "keylogger",
    "ransomware",
    "remote-access-trojan",
    "resource-exploitation",
    "rogue-security-software",
    "rootkit",
    "screen-capture",
    "spyware",
    "trojan",
    "unknown",
    "virus",
    "webshell",
    "wiper",
    "worm",
)

IDENTITY_CLASSES: tuple[str, ...] = ("individual", "group", "system", "organization", "class")

THREAT_ACTOR_TYPES: tuple[str, ...] = (
    "activist",
    "competitor",
    "crime-syndicate",
    "criminal",
    "hacker",
    "insider-accidental",
    "insider-disgruntled",
    "nation-state",
    "sensationalist",
    "spy",
    "terrorist",
    "unknown",
)

PATTERN_TYPES: tuple[str, ...] = ("stix", "pcre", "sigma", "snort", "suricata", "yara")

# Industry sectors as used by OpenCTI (identity_class = "class")
SECTORS: tuple[str, ...] = (
    "Agriculture",
    "Aerospace",
    "Automotive",
    "Chemical",
    "Civil Society",
    "Communications",
    "Construction",
    "Defense",
    "Education",
    "Energy",
    "Entertainment",
    "Finance",
    "Government",
    "Healthcare",
    "Hospitality",
    "Infrastructure",
    "Insurance",
    "Legal",
    "Manufacturing",
    "Mining",
    "Non-profit",
    "Pharmaceuticals",
    "Retail",
    "Technology",
    "Telecommunications",
    "Transportation",
    "Utilities",
)

HASH_ALGORITHMS: tuple[str, ...] = ("MD5", "SHA-1", "SHA-256", "SHA-512")
