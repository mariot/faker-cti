import re

import pytest
import stix2

from faker_cti.data.stix import OPENCTI_OBSERVABLE_ENTITY_TYPES, TLP_MARKINGS
from faker_cti.opencti import CONNECTOR_TYPES, OPENCTI_ADMIN_ID

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
SUPPORTED = [
    "IPv4-Addr",
    "IPv6-Addr",
    "Domain-Name",
    "Hostname",
    "Url",
    "Email-Addr",
    "Mac-Addr",
    "StixFile",
]


@pytest.mark.parametrize("entity_type", [*SUPPORTED, None])
def test_enrichment_message_is_consistent(fake, entity_type):
    message = fake.opencti_enrichment_message(entity_type)
    entity = message["enrichment_entity"]
    stix_entity = message["stix_entity"]

    assert message["event_type"] == "INTERNAL_ENRICHMENT"
    assert message["entity_type"] == entity["entity_type"] == stix_entity["x_opencti_type"]
    assert message["entity_id"] == entity["standard_id"] == stix_entity["id"]
    assert stix_entity["x_opencti_id"] == entity["id"]
    assert re.fullmatch(UUID, entity["id"])
    assert entity["observable_value"] == entity["value"]
    assert entity["x_opencti_score"] == stix_entity["x_opencti_score"]
    assert message["stix_objects"] == [stix_entity]
    assert [m["standard_id"] for m in entity["objectMarking"]] == stix_entity.get(
        "object_marking_refs", []
    )
    assert entity["objectMarkingIds"] == [m["id"] for m in entity["objectMarking"]]
    assert entity["creators"][0]["id"] == OPENCTI_ADMIN_ID


@pytest.mark.parametrize("entity_type", ["IPv4-Addr", "Domain-Name", "Url", "Email-Addr"])
def test_enrichment_standard_id_is_the_real_stix_id(fake, entity_type):
    message = fake.opencti_enrichment_message(entity_type, value=None)
    stix_type = message["stix_entity"]["type"]
    parsed = stix2.parse(
        {"type": stix_type, "spec_version": "2.1", "value": message["stix_entity"]["value"]}
    )
    assert message["entity_id"] == parsed.id


def test_enrichment_message_with_explicit_values(fake):
    message = fake.opencti_enrichment_message("ipv4-addr", "1.2.3.4", marking="red", score=80)
    assert message["entity_type"] == "IPv4-Addr"
    assert message["entity_id"] == stix2.IPv4Address(value="1.2.3.4").id
    assert message["enrichment_entity"]["observable_value"] == "1.2.3.4"
    assert message["stix_entity"]["object_marking_refs"] == [TLP_MARKINGS["TLP:RED"]]
    assert message["enrichment_entity"]["objectMarking"][0]["definition"] == "TLP:RED"
    assert message["stix_entity"]["x_opencti_score"] == 80


def test_file_enrichment_uses_the_hash_as_value(fake):
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    message = fake.opencti_enrichment_message("StixFile", sha256)
    assert message["stix_entity"]["hashes"] == {"SHA-256": sha256}
    assert message["enrichment_entity"]["observable_value"] == sha256
    stix2.parse(message["stix_entity"], allow_custom=True)


def test_unsupported_observable_type(fake):
    with pytest.raises(ValueError, match="Process"):
        fake.opencti_enrichment_message("Process")


def test_enrichment_entity_overrides(fake):
    entity = fake.opencti_enrichment_entity("Url", internal_id="i", standard_id="url--s")
    assert (entity["id"], entity["standard_id"]) == ("i", "url--s")


def test_marking_and_author(fake):
    marking = fake.opencti_marking("amber+strict")
    assert marking["definition"] == "TLP:AMBER+STRICT"
    assert marking["standard_id"] == TLP_MARKINGS["TLP:AMBER+STRICT"]
    author = fake.opencti_author("Filigran")
    assert author["id"] == "identity--8cb00c79-ab20-5ed4-b37d-337241b96a29"
    stix2.parse(author, allow_custom=True)


def test_types(fake):
    assert fake.opencti_observable_type() in OPENCTI_OBSERVABLE_ENTITY_TYPES.values()
    assert re.fullmatch(r"[A-Z][A-Za-z-]+", fake.opencti_entity_type())
    assert 0 <= fake.opencti_score() <= 100
    assert 0 <= fake.opencti_confidence() <= 100


@pytest.mark.parametrize("connector_type", CONNECTOR_TYPES)
def test_connector_config(fake, connector_type):
    config = fake.opencti_connector_config(connector_type, name="Test")
    assert config["opencti"]["url"] == "http://localhost:8080"
    assert re.fullmatch(UUID, config["opencti"]["token"])
    assert config["connector"]["type"] == connector_type
    assert config["connector"]["name"] == "Test"
    assert ("duration_period" in config["connector"]) is (connector_type == "EXTERNAL_IMPORT")
    assert re.fullmatch(r"P(T\d+[MH]|\d+D)", fake.opencti_duration_period())


def test_connector_env(fake):
    env = fake.opencti_connector_env("INTERNAL_ENRICHMENT")
    assert env["CONNECTOR_TYPE"] == "INTERNAL_ENRICHMENT"
    assert env["CONNECTOR_AUTO"] in {"true", "false"}
    assert {"OPENCTI_URL", "OPENCTI_TOKEN", "CONNECTOR_ID", "CONNECTOR_SCOPE"} <= env.keys()
    assert all(isinstance(v, str) for v in env.values())


def test_work_id(fake):
    assert re.fullmatch(r"work_c_\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", fake.opencti_work_id("c"))
