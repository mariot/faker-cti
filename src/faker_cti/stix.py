from __future__ import annotations

from typing import Any

from faker.providers.date_time import Provider as DateTimeProvider

from faker_cti._utils import deterministic_uuid, random_datetime, random_uuid4, stix_timestamp
from faker_cti.data import mitre, stix
from faker_cti.threat_intel import ThreatIntelProvider

# Observable types whose single contributing property is ``value``
_VALUE_OBSERVABLES = ("domain-name", "email-addr", "ipv4-addr", "ipv6-addr", "mac-addr", "url")

_HASH_PRIORITY = ("MD5", "SHA-1", "SHA-256", "SHA-512")

_PATTERN_HASH_KEYS = {
    "MD5": "MD5",
    "SHA-1": "'SHA-1'",
    "SHA-256": "'SHA-256'",
    "SHA-512": "'SHA-512'",
}


_REPORT_TITLES = (
    "targets the energy sector with new loader",
    "campaign leverages phishing attachments",
    "deploys ransomware after VPN compromise",
    "abuses cloud storage for exfiltration",
    "exploits edge devices in espionage operation",
)


def _choose_one_hash(hashes: dict[str, str]) -> dict[str, str]:
    """Pick the hash contributing to a deterministic id, like the ``stix2`` library does."""
    for algorithm in _HASH_PRIORITY:
        if algorithm in hashes:
            return {algorithm: hashes[algorithm]}
    key = next(iter(hashes))
    return {key: hashes[key]}


class StixProvider(ThreatIntelProvider):
    """STIX 2.1 identifiers, vocabularies and ready-to-serialize objects (as plain dicts)."""

    __provider__ = "stix"

    # -- identifiers ----------------------------------------------------------------------

    def stix_id(self, stix_type: str | None = None, **contributing_properties: Any) -> str:
        """STIX identifier ``<type>--<uuid>``.

        Without properties a random UUIDv4 is used (what STIX producers do for SDOs/SROs).
        With properties, the identifier is the deterministic UUIDv5 the STIX 2.1 spec
        mandates for cyber observables, identical to ``stix2`` and ``pycti``::

            >>> fake.stix_id("ipv4-addr", value="1.2.3.4")
            'ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4'
        """
        stix_type = stix_type or self.stix_type()
        if not contributing_properties:
            return f"{stix_type}--{random_uuid4(self.generator.random)}"
        data = {k: v for k, v in contributing_properties.items() if v is not None}
        if "hashes" in data:
            data["hashes"] = _choose_one_hash(data["hashes"])
        return f"{stix_type}--{deterministic_uuid(data)}"

    def stix_type(self, category: str | None = None) -> str:
        """STIX object type. ``category`` is one of ``"sdo"``, ``"sco"`` or ``None`` (any)."""
        choices = {
            "sdo": stix.STIX_DOMAIN_OBJECT_TYPES,
            "sco": stix.STIX_CYBER_OBSERVABLE_TYPES,
            None: stix.STIX_DOMAIN_OBJECT_TYPES + stix.STIX_CYBER_OBSERVABLE_TYPES,
        }
        if category not in choices:
            raise ValueError(f"Unknown STIX category {category!r}, expected 'sdo', 'sco' or None")
        return self.random_element(choices[category])

    def stix_timestamp(self) -> str:
        """STIX 2.1 timestamp, e.g. ``2024-03-18T09:41:27.512Z``."""
        value = random_datetime(self.generator.random)
        milliseconds = self.generator.random.randint(0, 999)
        return stix_timestamp(value.replace(microsecond=milliseconds * 1000))

    # -- markings -------------------------------------------------------------------------

    def tlp_level(self) -> str:
        """TLP 2.0 level, e.g. ``TLP:AMBER+STRICT``."""
        return self.random_element([k for k in stix.TLP_MARKINGS if k != "TLP:WHITE"])

    def tlp_marking_id(self, level: str | None = None) -> str:
        """Well-known marking-definition id of a TLP level (random level if omitted)."""
        level = level or self.tlp_level()
        return stix.TLP_MARKINGS[self._normalize_marking(level, "TLP")]

    def pap_level(self) -> str:
        return self.random_element(tuple(stix.PAP_MARKINGS))

    def pap_marking_id(self, level: str | None = None) -> str:
        level = level or self.pap_level()
        return stix.PAP_MARKINGS[self._normalize_marking(level, "PAP")]

    def stix_marking_definition(self, level: str | None = None) -> dict[str, Any]:
        """TLP ``marking-definition`` object as OpenCTI emits it."""
        level = self._normalize_marking(level or self.tlp_level(), "TLP")
        return {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": stix.TLP_MARKINGS[level],
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "statement",
            "definition": {"statement": "custom"},
            "name": level,
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": level,
        }

    @staticmethod
    def _normalize_marking(level: str, prefix: str) -> str:
        level = level.upper()
        if not level.startswith(f"{prefix}:"):
            level = f"{prefix}:{level}"
        known = stix.TLP_MARKINGS if prefix == "TLP" else stix.PAP_MARKINGS
        if level not in known:
            raise ValueError(f"Unknown {prefix} level {level!r}, expected one of {sorted(known)}")
        return level

    # -- vocabularies ---------------------------------------------------------------------

    def stix_relationship_type(self) -> str:
        return self.random_element(stix.RELATIONSHIP_TYPES)

    def stix_report_type(self) -> str:
        return self.random_element(stix.REPORT_TYPES)

    def stix_indicator_type(self) -> str:
        return self.random_element(stix.INDICATOR_TYPES)

    def stix_malware_type(self) -> str:
        return self.random_element(stix.MALWARE_TYPES)

    def stix_identity_class(self) -> str:
        return self.random_element(stix.IDENTITY_CLASSES)

    def stix_threat_actor_type(self) -> str:
        return self.random_element(stix.THREAT_ACTOR_TYPES)

    def stix_pattern_type(self) -> str:
        return self.random_element(stix.PATTERN_TYPES)

    def industry_sector(self) -> str:
        return self.random_element(stix.SECTORS)

    def stix_kill_chain_phase(self) -> dict[str, str]:
        """MITRE ATT&CK kill chain phase, e.g. ``{"kill_chain_name": "mitre-attack", ...}``."""
        return {
            "kill_chain_name": mitre.KILL_CHAIN_NAME,
            "phase_name": self.kill_chain_phase_name(),
        }

    # -- objects --------------------------------------------------------------------------

    def stix_external_reference(self, source_name: str | None = None) -> dict[str, str]:
        if source_name is None and self.generator.random.random() < 0.5:
            technique = self.mitre_attack_technique()
            return {
                "source_name": "mitre-attack",
                "external_id": technique["external_id"],
                "url": technique["url"],
            }
        source_name = source_name or self.generator.company()
        return {
            "source_name": source_name,
            "description": self.generator.sentence(),
            "url": f"{self.generator.url()}reports/{self.generator.slug()}",
            "external_id": random_uuid4(self.generator.random),
        }

    def stix_observable_value(self, stix_type: str) -> str:
        """Value of a value-based observable (``ipv4-addr``, ``domain-name``, ``url``...)."""
        # delegate to Faker's built-in internet provider
        generators = {
            "domain-name": self.generator.domain_name,
            "email-addr": self.generator.email,
            "hostname": self.generator.hostname,
            "ipv4-addr": self.generator.ipv4,
            "ipv6-addr": self.generator.ipv6,
            "mac-addr": self.generator.mac_address,
            "url": self.generator.url,
        }
        if stix_type not in generators:
            raise ValueError(f"{stix_type!r} is not a value-based observable: {sorted(generators)}")
        return generators[stix_type]()

    def stix_observable(
        self, stix_type: str | None = None, value: str | None = None, **extra: Any
    ) -> dict[str, Any]:
        """Cyber observable dict with a spec-compliant deterministic id.

        Supported types: value-based observables, ``file``, ``autonomous-system`` and
        ``mutex``. ``extra`` keys are merged in (``x_opencti_score``, ``object_marking_refs``...).
        """
        stix_type = stix_type or self.random_element(_VALUE_OBSERVABLES + ("file",))
        observable: dict[str, Any] = {"type": stix_type, "spec_version": "2.1"}
        if stix_type == "file":
            observable["hashes"] = self.file_hashes()
            observable["name"] = value or self.generator.file_name(
                extension=self.random_element(("exe", "dll", "ps1", "js", "docm", "zip"))
            )
            contributing = {"hashes": observable["hashes"], "name": observable["name"]}
        elif stix_type == "autonomous-system":
            observable["number"] = int(value) if value else self.autonomous_system_number()
            observable["name"] = f"{self.generator.company()} ASN"
            contributing = {"number": observable["number"]}
        elif stix_type == "mutex":
            observable["name"] = value or self.mutex_name()
            contributing = {"name": observable["name"]}
        else:
            observable["value"] = value or self.stix_observable_value(stix_type)
            contributing = {"value": observable["value"]}
        observable = {"id": self.stix_id(stix_type, **contributing), **observable, **extra}
        return observable

    def stix_pattern(self, stix_type: str | None = None, value: str | None = None) -> str:
        """STIX pattern matching one observable, e.g. ``[ipv4-addr:value = '192.0.2.10']``."""
        stix_type = stix_type or self.random_element(_VALUE_OBSERVABLES + ("file",))
        if stix_type == "file":
            algorithm = self.random_element(("MD5", "SHA-1", "SHA-256"))
            value = value or self.file_hashes((algorithm,))[algorithm]
            return f"[file:hashes.{_PATTERN_HASH_KEYS[algorithm]} = '{value}']"
        value = value or self.stix_observable_value(stix_type)
        return f"[{stix_type}:value = '{value}']"

    def stix_indicator(
        self, stix_type: str | None = None, value: str | None = None, **extra: Any
    ) -> dict[str, Any]:
        """``indicator`` SDO built on :meth:`stix_pattern`."""
        stix_type = stix_type or self.random_element(_VALUE_OBSERVABLES + ("file",))
        pattern = self.stix_pattern(stix_type, value)
        created = self.stix_timestamp()
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            # same as pycti Indicator.generate_id(pattern)
            "id": self.stix_id("indicator", pattern=pattern.strip()),
            "created": created,
            "modified": created,
            "name": pattern.split(" = ")[1].rstrip("]").strip("'"),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": created,
            "indicator_types": [self.stix_indicator_type()],
            "kill_chain_phases": [self.stix_kill_chain_phase()],
            "labels": self.generator.words(2),
            "confidence": self.generator.random.randint(0, 100),
            "object_marking_refs": [self.tlp_marking_id()],
            "x_opencti_score": self.generator.random.randint(0, 100),
            "x_opencti_main_observable_type": stix.OPENCTI_OBSERVABLE_ENTITY_TYPES.get(stix_type),
        }
        indicator.update(extra)
        return indicator

    def stix_relationship(
        self,
        source_ref: str | None = None,
        target_ref: str | None = None,
        relationship_type: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """``relationship`` SRO, id computed like pycti ``StixCoreRelationship.generate_id``."""
        created = self.stix_timestamp()
        relationship_type = relationship_type or self.stix_relationship_type()
        source_ref = source_ref or self.stix_id("indicator")
        target_ref = target_ref or self.stix_id("malware")
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": self.stix_id(
                "relationship",
                relationship_type=relationship_type,
                source_ref=source_ref,
                target_ref=target_ref,
            ),
            "created": created,
            "modified": created,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
        }
        relationship.update(extra)
        return relationship

    # -- domain objects -------------------------------------------------------------------
    # Ids follow the pycti ``generate_id`` conventions so they equal what OpenCTI computes.

    def _sdo(self, stix_type: str, stix_id: str, extra: dict[str, Any], **properties: Any):
        created = self.stix_timestamp()
        sdo = {
            "type": stix_type,
            "spec_version": "2.1",
            "id": stix_id,
            "created": created,
            "modified": created,
            **properties,
        }
        sdo.update(extra)
        return sdo

    def _named_id(self, stix_type: str, name: str, **properties: Any) -> str:
        return self.stix_id(stix_type, name=name.lower().strip(), **properties)

    def stix_attack_pattern(self, technique_id: str | None = None, **extra: Any) -> dict[str, Any]:
        """MITRE ATT&CK ``attack-pattern`` (id from ``x_mitre_id`` like pycti)."""
        techniques = {t[0]: t for t in mitre.TECHNIQUES}
        if technique_id is None:
            technique = self.mitre_attack_technique()
        elif technique_id in techniques:
            _, name, phase = techniques[technique_id]
            technique = {
                "external_id": technique_id,
                "name": name,
                "phase_name": phase,
                "url": "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/"),
            }
        else:
            raise ValueError(f"Unknown technique {technique_id!r}")
        return self._sdo(
            "attack-pattern",
            self.stix_id("attack-pattern", x_mitre_id=technique["external_id"].lower()),
            extra,
            name=technique["name"],
            x_mitre_id=technique["external_id"],
            kill_chain_phases=[
                {"kill_chain_name": mitre.KILL_CHAIN_NAME, "phase_name": technique["phase_name"]}
            ],
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": technique["external_id"],
                    "url": technique["url"],
                }
            ],
        )

    def stix_malware(self, name: str | None = None, **extra: Any) -> dict[str, Any]:
        name = name or self.malware_family()
        return self._sdo(
            "malware",
            self._named_id("malware", name),
            extra,
            name=name,
            is_family=True,
            malware_types=[self.stix_malware_type()],
        )

    def stix_tool(self, name: str | None = None, **extra: Any) -> dict[str, Any]:
        name = name or self.threat_tool()
        return self._sdo("tool", self._named_id("tool", name), extra, name=name)

    def stix_intrusion_set(self, name: str | None = None, **extra: Any) -> dict[str, Any]:
        profile = self.intrusion_set_profile()
        name = name or profile["name"]
        aliases = profile["aliases"] if name == profile["name"] else []
        return self._sdo(
            "intrusion-set",
            self._named_id("intrusion-set", name),
            extra,
            name=name,
            aliases=aliases,
        )

    def stix_threat_actor(self, name: str | None = None, **extra: Any) -> dict[str, Any]:
        """``threat-actor`` (OpenCTI ``Threat-Actor-Group``)."""
        name = name or self.intrusion_set()
        return self._sdo(
            "threat-actor",
            self._named_id("threat-actor", name, opencti_type="Threat-Actor-Group"),
            extra,
            name=name,
            threat_actor_types=[self.stix_threat_actor_type()],
        )

    def stix_vulnerability(self, name: str | None = None, **extra: Any) -> dict[str, Any]:
        name = name or self.cve_id()
        return self._sdo(
            "vulnerability",
            self._named_id("vulnerability", name),
            extra,
            name=name,
            external_references=[
                {
                    "source_name": "cve",
                    "external_id": name,
                    "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                }
            ],
        )

    def stix_identity(
        self, name: str | None = None, identity_class: str | None = None, **extra: Any
    ) -> dict[str, Any]:
        """``identity``: an organization by default, a sector when ``identity_class="class"``."""
        identity_class = identity_class or "organization"
        if name is None:
            name = self.industry_sector() if identity_class == "class" else self.generator.company()
        return self._sdo(
            "identity",
            self.stix_id("identity", name=name.lower().strip(), identity_class=identity_class),
            extra,
            name=name,
            identity_class=identity_class,
        )

    def stix_location(self, country_code: str | None = None, **extra: Any) -> dict[str, Any]:
        """Country ``location`` (name and ISO code taken from Faker's country table)."""
        countries = {c.alpha_2_code: c for c in DateTimeProvider.countries}
        if country_code is None:
            country = self.random_element(DateTimeProvider.countries)
        elif country_code.upper() in countries:
            country = countries[country_code.upper()]
        else:
            raise ValueError(f"Unknown country code {country_code!r}")
        return self._sdo(
            "location",
            self._named_id("location", country.name, x_opencti_location_type="Country"),
            extra,
            name=country.name,
            country=country.alpha_2_code,
            x_opencti_location_type="Country",
        )

    def stix_report(
        self, object_refs: list[str] | None = None, name: str | None = None, **extra: Any
    ) -> dict[str, Any]:
        """``report`` referencing ``object_refs`` (defaults to a few fresh ids)."""
        name = name or f"{self.intrusion_set()} {self.random_element(_REPORT_TITLES)}"
        published = self.stix_timestamp()
        if object_refs is None:
            object_refs = [self.stix_id("indicator"), self.stix_id("malware")]
        return self._sdo(
            "report",
            self._named_id("report", name, published=published),
            extra,
            name=name,
            description=self.generator.paragraph(),
            published=published,
            report_types=[self.stix_report_type()],
            object_refs=list(object_refs),
            object_marking_refs=[self.tlp_marking_id()],
        )

    def stix_bundle(self, objects: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """``bundle`` wrapping ``objects`` (defaults to a few indicators)."""
        if objects is None:
            objects = [self.stix_indicator() for _ in range(self.generator.random.randint(1, 3))]
        return {"type": "bundle", "id": self.stix_id("bundle"), "objects": list(objects)}
