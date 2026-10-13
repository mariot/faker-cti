"""Publicly documented threat names and well-known values.

Every name below is public knowledge (MITRE ATT&CK groups/software, vendor reports).
"""

MALWARE_FAMILIES: tuple[str, ...] = (
    "AgentTesla",
    "Akira",
    "AsyncRAT",
    "BlackCat",
    "Brute Ratel C4",
    "Cobalt Strike",
    "Conti",
    "Emotet",
    "FormBook",
    "IcedID",
    "LockBit",
    "Mirai",
    "njRAT",
    "PlugX",
    "QakBot",
    "Raccoon Stealer",
    "RedLine Stealer",
    "Remcos",
    "Ryuk",
    "ShadowPad",
    "Sliver",
    "TrickBot",
    "WannaCry",
)

TOOLS: tuple[str, ...] = (
    "AdFind",
    "BloodHound",
    "Impacket",
    "Mimikatz",
    "Nmap",
    "PsExec",
    "Rclone",
    "Rubeus",
    "SharpHound",
)

# (name, MITRE group id, aliases)
INTRUSION_SETS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("APT28", "G0007", ("Fancy Bear", "Sofacy", "Forest Blizzard")),
    ("APT29", "G0016", ("Cozy Bear", "Midnight Blizzard", "NOBELIUM")),
    ("APT41", "G0096", ("Wicked Panda", "Brass Typhoon")),
    ("FIN7", "G0046", ("Carbon Spider", "Sangria Tempest")),
    ("Kimsuky", "G0094", ("Velvet Chollima", "Emerald Sleet")),
    ("Lazarus Group", "G0032", ("Hidden Cobra", "Diamond Sleet")),
    ("MuddyWater", "G0069", ("Static Kitten", "Mango Sandstorm")),
    ("OilRig", "G0049", ("APT34", "Helix Kitten")),
    ("Sandworm Team", "G0034", ("APT44", "Seashell Blizzard")),
    ("Scattered Spider", "G1015", ("Octo Tempest", "UNC3944")),
    ("Turla", "G0010", ("Snake", "Venomous Bear", "Secret Blizzard")),
    ("Wizard Spider", "G0102", ("UNC1878", "Periwinkle Tempest")),
)

# Vulnerabilities frequently used as fixtures (all real, public CVEs).
NOTABLE_CVES: tuple[str, ...] = (
    "CVE-2017-0144",
    "CVE-2021-26855",
    "CVE-2021-44228",
    "CVE-2022-26134",
    "CVE-2023-23397",
    "CVE-2023-27350",
    "CVE-2023-34362",
    "CVE-2023-4966",
    "CVE-2024-3400",
    "CVE-2024-21762",
    "CVE-2025-24813",
)

CWES: tuple[str, ...] = (
    "CWE-20",
    "CWE-22",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-287",
    "CWE-502",
    "CWE-787",
    "CWE-918",
)

# (vendor, product) as spelled in the NVD CPE dictionary
CPE_PRODUCTS: tuple[tuple[str, str], ...] = (
    ("apache", "http_server"),
    ("apache", "tomcat"),
    ("atlassian", "confluence_server"),
    ("citrix", "netscaler_adc"),
    ("fortinet", "fortios"),
    ("ivanti", "connect_secure"),
    ("microsoft", "exchange_server"),
    ("nginx", "nginx"),
    ("openssl", "openssl"),
    ("paloaltonetworks", "pan-os"),
    ("progress", "moveit_transfer"),
    ("vmware", "vcenter_server"),
)

# Private ASN range (RFC 6996)
PRIVATE_ASN_RANGE: tuple[int, int] = (64512, 65534)

# Hashes of well-known, harmless content
EMPTY_FILE_HASHES: dict[str, str] = {
    "MD5": "d41d8cd98f00b204e9800998ecf8427e",
    "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
EICAR_HASHES: dict[str, str] = {
    "MD5": "44d88612fea8a8f36de82e1278abb02f",
    "SHA-1": "3395856ce81f2b7382dee72602f798b642f14140",
    "SHA-256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
}
