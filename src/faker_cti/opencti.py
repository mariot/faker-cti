from __future__ import annotations

from typing import Any

from faker_cti._utils import random_datetime, random_uuid4, stix_timestamp
from faker_cti.data import stix
from faker_cti.stix import StixProvider

# Internal id of the built-in OpenCTI admin user
OPENCTI_ADMIN_ID = "88ec0c6a-13ce-5e39-b486-354fe4a7084f"

CONNECTOR_TYPES = (
    "EXTERNAL_IMPORT",
    "INTERNAL_ENRICHMENT",
    "INTERNAL_IMPORT_FILE",
    "INTERNAL_EXPORT_FILE",
    "STREAM",
)

_DURATION_PERIODS = (
    "PT5M",
    "PT10M",
    "PT15M",
    "PT30M",
    "PT1H",
    "PT2H",
    "PT6H",
    "PT24H",
    "P1D",
    "P7D",
)

_SCOPES = {
    "EXTERNAL_IMPORT": ("report,indicator,malware", "vulnerability", "indicator", "identity"),
    "INTERNAL_ENRICHMENT": (
        "IPv4-Addr",
        "Domain-Name",
        "StixFile",
        "Url",
        "IPv4-Addr,IPv6-Addr",
        "Url,Domain-Name,Hostname",
    ),
    "INTERNAL_IMPORT_FILE": ("application/pdf", "text/plain", "application/json,text/csv"),
    "INTERNAL_EXPORT_FILE": ("application/json", "text/csv", "text/plain"),
    "STREAM": ("live",),
}


class OpenCTIProvider(StixProvider):
    """Shapes exchanged between OpenCTI and its connectors (pycti / connectors-sdk)."""

    __provider__ = "opencti"

    # -- scalars --------------------------------------------------------------------------

    def opencti_internal_id(self) -> str:
        """OpenCTI internal id (UUIDv4, distinct from the STIX ``standard_id``)."""
        return random_uuid4(self.generator.random)

    def opencti_score(self) -> int:
        return self.generator.random.randint(0, 100)

    def opencti_confidence(self) -> int:
        return self.random_element((0, 15, 50, 75, 85, 100))

    def opencti_label(self) -> str:
        return self.random_element(
            (
                "malicious-activity",
                "phishing",
                "c2",
                "botnet",
                "ransomware",
                "scanner",
                "tor-exit",
                "vpn",
                "osint",
                "apt",
                "credential-theft",
                "infostealer",
            )
        )

    def opencti_observable_type(self) -> str:
        """OpenCTI observable entity type, e.g. ``IPv4-Addr`` or ``StixFile``."""
        return self.random_element(tuple(stix.OPENCTI_OBSERVABLE_ENTITY_TYPES.values()))

    def opencti_entity_type(self) -> str:
        """OpenCTI domain entity type, e.g. ``Intrusion-Set`` or ``Report``."""
        return self.random_element(tuple(stix.OPENCTI_DOMAIN_ENTITY_TYPES.values()))

    def opencti_timestamp(self) -> str:
        return stix_timestamp(random_datetime(self.generator.random))

    # -- connector configuration ----------------------------------------------------------

    def opencti_connector_type(self) -> str:
        return self.random_element(CONNECTOR_TYPES)

    def opencti_connector_scope(self, connector_type: str | None = None) -> str:
        connector_type = connector_type or self.opencti_connector_type()
        return self.random_element(_SCOPES[connector_type])

    def opencti_duration_period(self) -> str:
        """ISO 8601 duration accepted by ``CONNECTOR_DURATION_PERIOD``."""
        return self.random_element(_DURATION_PERIODS)

    def opencti_work_id(self, connector_id: str | None = None) -> str:
        """Work id as returned by ``helper.api.work.initiate_work``."""
        connector_id = connector_id or random_uuid4(self.generator.random)
        timestamp = random_datetime(self.generator.random).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        return f"work_{connector_id}_{timestamp}Z"

    def opencti_connector_config(
        self, connector_type: str | None = None, name: str | None = None
    ) -> dict[str, dict[str, Any]]:
        """Nested settings dict as loaded by connectors from ``config.yml`` / env vars."""
        connector_type = connector_type or self.opencti_connector_type()
        config: dict[str, dict[str, Any]] = {
            "opencti": {
                "url": "http://localhost:8080",
                "token": random_uuid4(self.generator.random),
            },
            "connector": {
                "id": random_uuid4(self.generator.random),
                "type": connector_type,
                "name": name or f"{self.generator.company()} Connector",
                "scope": self.opencti_connector_scope(connector_type),
                "log_level": self.random_element(("debug", "info", "warning", "error")),
            },
        }
        if connector_type == "EXTERNAL_IMPORT":
            config["connector"]["duration_period"] = self.opencti_duration_period()
        if connector_type == "INTERNAL_ENRICHMENT":
            config["connector"]["auto"] = self.generator.random.random() < 0.5
        return config

    def opencti_connector_env(
        self, connector_type: str | None = None, name: str | None = None
    ) -> dict[str, str]:
        """Same as :meth:`opencti_connector_config`, flattened to environment variables."""
        config = self.opencti_connector_config(connector_type, name)
        return {
            f"{section.upper()}_{key.upper()}": str(value).lower()
            if isinstance(value, bool)
            else str(value)
            for section, values in config.items()
            for key, value in values.items()
        }

    # -- entities -------------------------------------------------------------------------

    def opencti_marking(self, level: str | None = None) -> dict[str, Any]:
        """Marking as returned in an entity ``objectMarking`` list."""
        level = level or self.tlp_level()
        return {
            "id": random_uuid4(self.generator.random),
            "standard_id": self.tlp_marking_id(level),
            "entity_type": "Marking-Definition",
            "definition_type": "TLP",
            "definition": self._normalize_marking(level, "TLP"),
        }

    def opencti_author(self, name: str | None = None) -> dict[str, Any]:
        """Organization ``identity`` used as ``created_by_ref`` by connectors."""
        name = name or self.generator.company()
        return {
            "type": "identity",
            "spec_version": "2.1",
            # same as pycti Identity.generate_id(name, "organization")
            "id": self.stix_id(
                "identity", name=name.lower().strip(), identity_class="organization"
            ),
            "name": name,
            "identity_class": "organization",
            "x_opencti_organization_type": "vendor",
        }

    def opencti_stix_entity(
        self,
        entity_type: str | None = None,
        value: str | None = None,
        score: int | None = None,
        internal_id: str | None = None,
    ) -> dict[str, Any]:
        """``stix_entity`` of an enrichment message (STIX object extended by OpenCTI)."""
        stix_type, entity_type = self._resolve_observable_type(entity_type)
        observable = self._observable(stix_type, value)
        return {
            **observable,
            "x_opencti_score": self.opencti_score() if score is None else score,
            "x_opencti_description": self.generator.sentence(),
            "x_opencti_id": internal_id or self.opencti_internal_id(),
            "x_opencti_type": entity_type,
            "x_opencti_labels": [self.opencti_label()],
        }

    def opencti_enrichment_entity(
        self,
        entity_type: str | None = None,
        value: str | None = None,
        marking: str | None = None,
        score: int | None = None,
        internal_id: str | None = None,
        standard_id: str | None = None,
    ) -> dict[str, Any]:
        """``enrichment_entity`` of an enrichment message (OpenCTI GraphQL representation)."""
        stix_type, entity_type = self._resolve_observable_type(entity_type)
        observable = self._observable(stix_type, value)
        value = self._observable_value(observable)
        has_marking = marking is not None or self.generator.random.random() < 0.8
        markings = [self.opencti_marking(marking)] if has_marking else []
        created_at = self.opencti_timestamp()
        return {
            "id": internal_id or self.opencti_internal_id(),
            "standard_id": standard_id or observable["id"],
            "entity_type": entity_type,
            "parent_types": list(stix.OBSERVABLE_PARENT_TYPES),
            "spec_version": "2.1",
            "created_at": created_at,
            "updated_at": created_at,
            "objectOrganization": [],
            "creators": [{"id": OPENCTI_ADMIN_ID, "name": "admin"}],
            "createdBy": None,
            "createdById": None,
            "objectMarking": markings,
            "objectMarkingIds": [m["id"] for m in markings],
            "objectLabel": [],
            "objectLabelIds": [],
            "externalReferences": [],
            "externalReferencesIds": [],
            "indicators": [],
            "indicatorsIds": [],
            "importFiles": [],
            "importFilesIds": [],
            "observable_value": value,
            "value": value,
            "x_opencti_description": self.generator.sentence(),
            "x_opencti_score": self.opencti_score() if score is None else score,
        }

    def opencti_enrichment_message(
        self,
        entity_type: str | None = None,
        value: str | None = None,
        marking: str | None = None,
        score: int | None = None,
    ) -> dict[str, Any]:
        """Message received by ``INTERNAL_ENRICHMENT`` connectors in ``process_message``.

        ``entity_id``, ``stix_entity`` and ``enrichment_entity`` all describe the same
        observable: the ids, value, score and marking are consistent across the three.
        """
        stix_type, entity_type = self._resolve_observable_type(entity_type)
        value = value or self._observable_value(self._observable(stix_type))
        score = self.opencti_score() if score is None else score
        enrichment_entity = self.opencti_enrichment_entity(entity_type, value, marking, score)
        stix_entity = self.opencti_stix_entity(
            entity_type, value, score, internal_id=enrichment_entity["id"]
        )
        stix_entity["id"] = enrichment_entity["standard_id"]
        if enrichment_entity["objectMarking"]:
            stix_entity["object_marking_refs"] = [
                m["standard_id"] for m in enrichment_entity["objectMarking"]
            ]
        return {
            "event_type": "INTERNAL_ENRICHMENT",
            "entity_id": enrichment_entity["standard_id"],
            "entity_type": entity_type,
            "stix_entity": stix_entity,
            "stix_objects": [stix_entity],
            "enrichment_entity": enrichment_entity,
        }

    def _observable(self, stix_type: str, value: str | None = None) -> dict[str, Any]:
        """STIX observable; for files, ``value`` is the SHA-256 the observable is known by."""
        if stix_type != "file":
            return self.stix_observable(stix_type, value)
        observable = self.stix_observable("file")
        if value:
            observable["hashes"] = {"SHA-256": value}
            observable["id"] = self.stix_id(
                "file", hashes=observable["hashes"], name=observable["name"]
            )
        return observable

    @staticmethod
    def _observable_value(observable: dict[str, Any]) -> str:
        if observable["type"] == "file":
            return observable["hashes"]["SHA-256"]
        return observable["value"]

    def _resolve_observable_type(self, entity_type: str | None) -> tuple[str, str]:
        """Accept an OpenCTI entity type (``IPv4-Addr``) or STIX type (``ipv4-addr``)."""
        supported = (
            "IPv4-Addr",
            "IPv6-Addr",
            "Domain-Name",
            "Hostname",
            "Url",
            "Email-Addr",
            "Mac-Addr",
            "StixFile",
        )
        entity_type = entity_type or self.random_element(supported)
        for stix_type, opencti_type in stix.OPENCTI_OBSERVABLE_ENTITY_TYPES.items():
            if entity_type in (stix_type, opencti_type) and opencti_type in supported:
                return stix_type, opencti_type
        raise ValueError(
            f"Unsupported observable type {entity_type!r}, expected one of {supported}"
        )
