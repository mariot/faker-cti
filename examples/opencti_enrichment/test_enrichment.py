"""A toy enrichment connector tested with faker-cti factories.

The connector reads the observable from the message, "looks it up", and returns a
STIX bundle containing the original observable plus a note. This is the structure of
most OpenCTI internal enrichment connectors.
"""

import pytest
import stix2

from .factories import EnrichmentMessageFactory, HashClassificationFactory, StixIpv4EntityFactory


class ToyEnrichmentConnector:
    def __init__(self, scope: list[str], lookup):
        self.scope = scope
        self.lookup = lookup

    def process_message(self, data: dict) -> dict | None:
        if data["entity_type"] not in self.scope:
            return None
        entity = data["stix_entity"]
        verdict = self.lookup(data["enrichment_entity"]["observable_value"])
        note = stix2.Note(
            content=f"Verdict: {verdict}",
            object_refs=[entity["id"]],
            object_marking_refs=entity.get("object_marking_refs", []),
            allow_custom=True,
        )
        return stix2.Bundle(objects=[*data["stix_objects"], note], allow_custom=True)


@pytest.fixture
def connector():
    return ToyEnrichmentConnector(scope=["IPv4-Addr", "Domain-Name"], lookup=lambda v: "malicious")


def test_out_of_scope_entity_is_ignored(connector):
    assert connector.process_message(EnrichmentMessageFactory(entity_type="Url")) is None


@pytest.mark.parametrize("entity_type", ["IPv4-Addr", "Domain-Name"])
def test_note_references_the_enriched_observable(connector, entity_type):
    message = EnrichmentMessageFactory(entity_type=entity_type)
    bundle = connector.process_message(message)
    note = bundle.objects[-1]
    assert note.object_refs == [message["entity_id"]]


def test_note_inherits_the_observable_marking(connector):
    message = EnrichmentMessageFactory(marking="amber+strict")
    note = connector.process_message(message).objects[-1]
    assert note.object_marking_refs == ["marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"]


def test_lookup_receives_the_observable_value():
    seen = []
    connector = ToyEnrichmentConnector(["IPv4-Addr"], lookup=lambda v: seen.append(v) or "ok")
    connector.process_message(EnrichmentMessageFactory(value="192.0.2.10"))
    assert seen == ["192.0.2.10"]


def test_field_level_factory_keeps_ids_consistent():
    entity = StixIpv4EntityFactory(value="1.2.3.4")
    assert entity.id == stix2.IPv4Address(value="1.2.3.4").id


def test_hash_classification_factory():
    classification = HashClassificationFactory()
    assert len(classification.sha256) == 64
    assert classification.threat_name.endswith(classification.malware_family)
