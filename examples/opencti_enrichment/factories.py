"""Factories for an OpenCTI *internal enrichment* connector.

Before faker-cti, connectors such as ``censys-enrichment`` or
``reversinglabs-spectra-analyze`` each declared ~500 lines of dataclasses and factories
to rebuild the enrichment message, and filled STIX ids with ``Faker("uuid4")``
(``"id": "3f0c..."`` instead of ``"ipv4-addr--3f0c..."``), so the fixtures did not
look like what OpenCTI sends.

The factories below build the same messages with valid, mutually consistent ids.
"""

from dataclasses import dataclass

import factory

from faker_cti import CtiProvider

factory.Faker.add_provider(CtiProvider)


class EnrichmentMessageFactory(factory.DictFactory):
    """Full ``process_message`` payload. Usage::

    EnrichmentMessageFactory()                                    # random observable
    EnrichmentMessageFactory(entity_type="Domain-Name")
    EnrichmentMessageFactory(entity_type="IPv4-Addr", value="192.0.2.1", marking="red")
    """

    class Params:
        entity_type = "IPv4-Addr"
        value = None
        marking = None
        score = None

    message = factory.Faker(
        "opencti_enrichment_message",
        entity_type=factory.SelfAttribute("..entity_type"),
        value=factory.SelfAttribute("..value"),
        marking=factory.SelfAttribute("..marking"),
        score=factory.SelfAttribute("..score"),
    )

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        return kwargs["message"]


@dataclass
class StixIpv4Entity:
    """Same model as ``StixIpv4Entity`` in censys-enrichment/tests/factories.py."""

    id: str
    value: str
    x_opencti_score: int
    x_opencti_description: str
    x_opencti_id: str
    external_references: list
    x_opencti_labels: list
    x_opencti_type: str = "IPv4-Addr"
    type: str = "ipv4-addr"
    spec_version: str = "2.1"


class StixIpv4EntityFactory(factory.Factory):
    """Field-by-field factory, for tests that keep their own models."""

    class Meta:
        model = StixIpv4Entity

    value = factory.Faker("ipv4")
    # deterministic STIX id derived from the value, exactly what stix2/pycti compute
    id = factory.Faker("stix_id", stix_type="ipv4-addr", value=factory.SelfAttribute("..value"))
    x_opencti_score = factory.Faker("opencti_score")
    x_opencti_description = factory.Faker("sentence")
    x_opencti_id = factory.Faker("opencti_internal_id")
    external_references = factory.List([factory.Faker("stix_external_reference")])
    x_opencti_labels = factory.List([factory.Faker("opencti_label")])


@dataclass
class HashClassification:
    """Same model as ``HashClassification`` in reversinglabs-spectra-analyze/tests."""

    sha1: str
    sha256: str
    md5: str
    classification: str
    riskscore: int
    malware_family: str
    threat_name: str


class HashClassificationFactory(factory.Factory):
    class Meta:
        model = HashClassification

    class Params:
        hashes = factory.Faker("file_hashes")

    md5 = factory.LazyAttribute(lambda o: o.hashes["MD5"])
    sha1 = factory.LazyAttribute(lambda o: o.hashes["SHA-1"])
    sha256 = factory.LazyAttribute(lambda o: o.hashes["SHA-256"])
    classification = "malicious"
    riskscore = factory.Faker("random_int", min=1, max=10)
    # instead of a hard-coded MALWARE_NAMES list copied in every connector
    malware_family = factory.Faker("malware_family")
    threat_name = factory.LazyAttribute(lambda o: f"Win32.Trojan.{o.malware_family}")
