"""Generic contract every formatter must honour."""

import inspect

import factory
import pytest
from faker import Faker
from faker.providers import BaseProvider

from faker_cti import (
    CtiProvider,
    OpenAEVProvider,
    OpenCTIProvider,
    StixProvider,
    ThreatIntelProvider,
)

# Formatters requiring an argument
_REQUIRED_ARGS = {
    "defang": ("https://203.0.113.5/a",),
    "stix_observable_value": ("ipv4-addr",),
    "openaev_signature_value": ("hostname",),
}


def _formatters(provider: type[BaseProvider]) -> list[str]:
    base = set(dir(BaseProvider))
    return sorted(
        name
        for name, member in inspect.getmembers(provider, inspect.isfunction)
        if not name.startswith("_") and name not in base
    )


ALL_FORMATTERS = _formatters(CtiProvider)


@pytest.mark.parametrize("formatter", ALL_FORMATTERS)
def test_every_formatter_returns_a_value(fake, formatter):
    value = getattr(fake, formatter)(*_REQUIRED_ARGS.get(formatter, ()))
    assert value is not None and value != ""


@pytest.mark.parametrize("formatter", ALL_FORMATTERS)
def test_every_formatter_is_reproducible_with_a_seed(formatter):
    args = _REQUIRED_ARGS.get(formatter, ())
    values = []
    for _ in range(2):
        fake = Faker()
        fake.add_provider(CtiProvider)
        fake.seed_instance(99)
        values.append(getattr(fake, formatter)(*args))
    assert values[0] == values[1]


@pytest.mark.parametrize("formatter", ALL_FORMATTERS)
def test_formatters_do_not_shadow_faker_builtins(formatter):
    vanilla = Faker()
    assert not hasattr(vanilla, formatter), f"{formatter} already exists in Faker"


@pytest.mark.parametrize(
    "provider", [ThreatIntelProvider, StixProvider, OpenCTIProvider, OpenAEVProvider, CtiProvider]
)
def test_providers_can_be_registered_individually(provider):
    fake = Faker()
    fake.add_provider(provider)
    for formatter in _formatters(provider):
        getattr(fake, formatter)(*_REQUIRED_ARGS.get(formatter, ()))


@pytest.mark.parametrize("locale", ["en_US", "fr_FR", "ja_JP", "de_DE"])
def test_works_with_any_locale(locale):
    fake = Faker(locale)
    fake.add_provider(CtiProvider)
    assert fake.opencti_enrichment_message()["event_type"] == "INTERNAL_ENRICHMENT"
    assert fake.openaev_expectation()["inject_expectation_signatures"]


def test_factory_boy_integration():
    factory.Faker.add_provider(CtiProvider)

    class Indicator(factory.DictFactory):
        id = factory.Faker("stix_id", stix_type="indicator")
        pattern = factory.Faker("stix_pattern", stix_type="ipv4-addr")
        object_marking_refs = factory.List([factory.Faker("tlp_marking_id", level="amber")])

    indicator = Indicator()
    assert indicator["id"].startswith("indicator--")
    assert indicator["pattern"].startswith("[ipv4-addr:value = '")
    assert indicator["object_marking_refs"] == [
        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    ]
