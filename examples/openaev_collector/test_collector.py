"""A toy collector matcher tested with faker-cti factories.

Collectors receive expectations from OpenAEV, fetch alerts from a security platform
and report ``Detected`` / ``Not Detected`` (or ``Prevented`` / ``Not Prevented``).
"""

import re

import pytest
from faker import Faker

from faker_cti import CtiProvider

from .factories import AlertFactory, ExpectationFactory

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# Same regex as the parent_process_parser of the OpenAEV SIEM collectors
IMPLANT = re.compile(rf"oaev-implant-({UUID})-agent-({UUID})")


def match(expectation, alerts) -> bool:
    wanted = {
        s.value
        for s in expectation.inject_expectation_signatures
        if s.type == "parent_process_name"
    }
    for alert in alerts:
        found = IMPLANT.search(alert.actor_process_image_name)
        if found and found.group(0) in wanted:
            return True
    return False


def result_for(expectation, alerts, collector_id):
    fake = Faker()
    fake.add_provider(CtiProvider)
    return fake.openaev_expectation_result(
        expectation.inject_expectation_type, match(expectation, alerts), collector_id
    )


def test_matching_alert_is_detected():
    expectation = ExpectationFactory()
    alerts = [AlertFactory(), AlertFactory(matching=expectation)]
    assert match(expectation, alerts)


def test_unrelated_alerts_are_not_detected():
    expectation = ExpectationFactory()
    assert not match(expectation, AlertFactory.build_batch(5))


def test_alert_from_another_inject_is_not_a_match():
    expectation = ExpectationFactory()
    other = AlertFactory(matching=ExpectationFactory())
    assert not match(expectation, [other])


def test_implant_name_encodes_inject_and_agent():
    expectation = ExpectationFactory(inject_id="0" * 8 + "-0000-4000-8000-" + "0" * 12)
    signature = expectation.inject_expectation_signatures[0]
    assert IMPLANT.fullmatch(signature.value).group(1).startswith("00000000")


@pytest.mark.parametrize(
    ("prevention", "matched", "label"),
    [
        (False, True, "Detected"),
        (False, False, "Not Detected"),
        (True, True, "Prevented"),
        (True, False, "Not Prevented"),
    ],
)
def test_result_payload(prevention, matched, label):
    expectation = ExpectationFactory(prevention=prevention)
    alerts = [AlertFactory(matching=expectation)] if matched else []
    result = result_for(expectation, alerts, "cortex-xdr--test")
    assert result["result"] == label
    assert result["is_success"] is matched
