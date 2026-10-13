from __future__ import annotations

import string

from faker.providers import BaseProvider

from faker_cti._utils import random_hex, random_uuid4
from faker_cti.data import mitre, threats

_SSDEEP_ALPHABET = string.ascii_letters + string.digits + "+/"


class ThreatIntelProvider(BaseProvider):
    """Threat intelligence vocabulary: hashes, vulnerabilities, ATT&CK and threat names.

    Plain network values (IP addresses, domains, URLs, emails...) are left to Faker's
    built-in ``internet`` provider: this provider only adds what Faker does not have.
    """

    __provider__ = "threat_intel"

    # -- network indicators -------------------------------------------------------------

    def autonomous_system_number(self) -> int:
        """Private-use ASN (RFC 6996)."""
        return self.generator.random.randint(*threats.PRIVATE_ASN_RANGE)

    def asn(self) -> str:
        """Autonomous system in ``AS<number>`` notation, e.g. ``AS64512``."""
        return f"AS{self.autonomous_system_number()}"

    def defang(self, value: str) -> str:
        """Defang an indicator the way threat reports do (``hxxp``, ``[.]``, ``[@]``)."""
        return (
            value.replace("http://", "hxxp://")
            .replace("https://", "hxxps://")
            .replace(".", "[.]")
            .replace("@", "[@]")
        )

    # -- file indicators ----------------------------------------------------------------

    def file_hashes(self, algorithms: tuple[str, ...] | list[str] | None = None) -> dict[str, str]:
        """Hashes dictionary keyed with STIX hash names, e.g. ``{"MD5": ..., "SHA-256": ...}``.

        Supported algorithms: ``MD5``, ``SHA-1``, ``SHA-256``, ``SHA-512``, ``SSDEEP``, ``TLSH``.
        """
        algorithms = algorithms or ("MD5", "SHA-1", "SHA-256")
        generators = {
            "MD5": self.generator.md5,
            "SHA-1": self.generator.sha1,
            "SHA-256": self.generator.sha256,
            "SHA-512": lambda: random_hex(self.generator.random, 128),
            "SSDEEP": self.ssdeep,
            "TLSH": self.tlsh,
        }
        unknown = set(algorithms) - generators.keys()
        if unknown:
            raise ValueError(f"Unsupported hash algorithm(s): {sorted(unknown)}")
        return {algorithm: generators[algorithm]() for algorithm in algorithms}

    def ssdeep(self) -> str:
        """Context triggered piecewise hash, e.g. ``1536:DovfkHU...:Dny7Vm6B...``."""
        block_size = self.random_element((48, 96, 192, 384, 768, 1536, 3072, 6144))
        rand = self.generator.random

        def chunk(n: int) -> str:
            return "".join(rand.choice(_SSDEEP_ALPHABET) for _ in range(n))

        return f"{block_size}:{chunk(rand.randint(30, 64))}:{chunk(rand.randint(15, 32))}"

    def tlsh(self) -> str:
        """Trend Micro Locality Sensitive Hash (version ``T1`` prefix + 70 hex chars)."""
        return "T1" + random_hex(self.generator.random, 70).upper()

    def mutex_name(self) -> str:
        prefix = self.random_element(("Global\\", "Local\\", ""))
        if self.generator.random.random() < 0.5:
            return f"{prefix}{{{random_uuid4(self.generator.random).upper()}}}"
        return f"{prefix}M_{random_hex(self.generator.random, 12)}"

    def windows_registry_key(self) -> str:
        return self.random_element(
            (
                "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "HKEY_CURRENT_USER\\Software\\Classes\\ms-settings\\shell\\open\\command",
            )
        )

    def x509_serial_number(self) -> str:
        """Certificate serial number as colon-separated hex bytes."""
        return ":".join(random_hex(self.generator.random, 2) for _ in range(16))

    # -- vulnerabilities ------------------------------------------------------------------

    def cve_id(self, year: int | None = None) -> str:
        """Syntactically valid CVE identifier, e.g. ``CVE-2024-31337``."""
        year = year or self.generator.random.randint(2015, 2025)
        return f"CVE-{year}-{self.generator.random.randint(1000, 59999):04d}"

    def notable_cve_id(self) -> str:
        """Well-known, real CVE often used as fixture (Log4Shell, PAN-OS, ...)."""
        return self.random_element(threats.NOTABLE_CVES)

    def cwe_id(self) -> str:
        return self.random_element(threats.CWES)

    def cpe23(
        self,
        vendor: str | None = None,
        product: str | None = None,
        version: str | None = None,
        part: str = "a",
    ) -> str:
        """CPE 2.3 formatted string, e.g. ``cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*``."""
        if vendor is None or product is None:
            default_vendor, default_product = self.random_element(threats.CPE_PRODUCTS)
            vendor = vendor or default_vendor
            product = product or default_product
        version = version or self.numerify("%.#.#")
        return f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    # -- MITRE ATT&CK -------------------------------------------------------------------

    def mitre_attack_technique(self) -> dict[str, str]:
        """Technique with its id, name, primary tactic and attack.mitre.org url."""
        technique_id, name, phase = self.random_element(mitre.TECHNIQUES)
        return {
            "external_id": technique_id,
            "name": name,
            "phase_name": phase,
            "url": "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/"),
        }

    def mitre_attack_technique_id(self, subtechnique: bool | None = None) -> str:
        """Technique id such as ``T1059`` or, with ``subtechnique=True``, ``T1059.001``."""
        ids = [t[0] for t in mitre.TECHNIQUES]
        if subtechnique is not None:
            ids = [i for i in ids if ("." in i) is subtechnique]
        return self.random_element(ids)

    def mitre_attack_tactic(self) -> dict[str, str]:
        tactic_id, name, phase = self.random_element(mitre.TACTICS)
        return {
            "external_id": tactic_id,
            "name": name,
            "phase_name": phase,
            "url": f"https://attack.mitre.org/tactics/{tactic_id}",
        }

    def mitre_attack_tactic_id(self) -> str:
        return self.random_element([t[0] for t in mitre.TACTICS])

    def kill_chain_phase_name(self) -> str:
        """``phase_name`` of a MITRE ATT&CK kill chain phase, e.g. ``defense-evasion``."""
        return self.random_element([t[2] for t in mitre.TACTICS])

    # -- threat names ---------------------------------------------------------------------

    def malware_family(self) -> str:
        return self.random_element(threats.MALWARE_FAMILIES)

    def threat_tool(self) -> str:
        """Offensive or dual-use tool commonly reported in intrusions (Mimikatz, PsExec...)."""
        return self.random_element(threats.TOOLS)

    def intrusion_set(self) -> str:
        """Publicly tracked intrusion set name, e.g. ``APT29``."""
        return self.random_element(threats.INTRUSION_SETS)[0]

    def intrusion_set_profile(self) -> dict:
        """Intrusion set with its MITRE group id and aliases."""
        name, group_id, aliases = self.random_element(threats.INTRUSION_SETS)
        return {"name": name, "external_id": group_id, "aliases": list(aliases)}

    def mitre_attack_group_id(self) -> str:
        return self.random_element(threats.INTRUSION_SETS)[1]
