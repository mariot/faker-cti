"""Faker providers for cyber threat intelligence and adversarial exposure validation tests.

Usage::

    from faker import Faker
    from faker_cti import CtiProvider

    fake = Faker()
    fake.add_provider(CtiProvider)
    fake.stix_id("indicator")
"""

from faker_cti.openaev import OpenAEVProvider
from faker_cti.opencti import OpenCTIProvider
from faker_cti.stix import StixProvider
from faker_cti.threat_intel import ThreatIntelProvider

__version__ = "0.1.0"


class CtiProvider(OpenCTIProvider, OpenAEVProvider):
    """Every faker-cti formatter in a single provider."""

    __provider__ = "cti"


# Lets Faker load the package by name: ``Faker(includes=["faker_cti"])`` or
# ``faker -i faker_cti stix_id`` on the command line.
Provider = CtiProvider


__all__ = [
    "CtiProvider",
    "OpenAEVProvider",
    "OpenCTIProvider",
    "Provider",
    "StixProvider",
    "ThreatIntelProvider",
]
