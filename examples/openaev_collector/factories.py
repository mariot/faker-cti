"""Factories for an OpenAEV *collector* (EDR/XDR alert matching).

Mirrors ``palo-alto-cortex-xdr/tests/factories.py``: there, the implant name was built
as ``f"oaev-implant-{uuid}"``, while the SIEM collectors' parser expects
``oaev-implant-<inject id>-agent-<agent id>``, and the alert was unrelated to the
expectation. Here, the alert is derived from the expectation so a "matching" alert
really matches.
"""

from dataclasses import dataclass, field

import factory

from faker_cti import CtiProvider

factory.Faker.add_provider(CtiProvider)


@dataclass
class ExpectationSignature:
    type: str
    value: str


@dataclass
class Expectation:
    """Subset of ``pyoaev...model.expectation.DetectionExpectation``."""

    inject_expectation_id: str
    inject_expectation_type: str
    inject_expectation_signatures: list[ExpectationSignature]


@dataclass
class Alert:
    """Subset of the Cortex XDR alert model."""

    alert_id: str
    severity: str
    action_pretty: str
    actor_process_image_name: str
    actor_process_command_line: str
    mitre_technique_ids: list[str] = field(default_factory=list)


class ExpectationFactory(factory.Factory):
    """``ExpectationFactory()`` / ``ExpectationFactory(prevention=True)``."""

    class Meta:
        model = Expectation

    class Params:
        prevention = False
        inject_id = factory.Faker("openaev_id")
        agent_id = factory.Faker("openaev_id")
        expectation_type = factory.LazyAttribute(
            lambda o: "PREVENTION" if o.prevention else "DETECTION"
        )
        raw = factory.Faker(
            "openaev_expectation",
            expectation_type=factory.SelfAttribute("..expectation_type"),
            inject_id=factory.SelfAttribute("..inject_id"),
            agent_id=factory.SelfAttribute("..agent_id"),
        )

    inject_expectation_id = factory.LazyAttribute(lambda o: o.raw["inject_expectation_id"])
    inject_expectation_type = factory.LazyAttribute(lambda o: o.raw["inject_expectation_type"])
    inject_expectation_signatures = factory.LazyAttribute(
        lambda o: [ExpectationSignature(**s) for s in o.raw["inject_expectation_signatures"]]
    )


class AlertFactory(factory.Factory):
    """Unrelated alert by default; ``AlertFactory(matching=expectation)`` for a hit."""

    class Meta:
        model = Alert

    class Params:
        matching = None
        inject_id = factory.Faker("openaev_id")
        agent_id = factory.Faker("openaev_id")

    alert_id = factory.Faker("openaev_id")
    severity = factory.Faker("random_element", elements=["low", "medium", "high"])
    action_pretty = "Detected (Reported)"
    actor_process_image_name = factory.LazyAttribute(
        lambda o: (
            next(
                s.value
                for s in o.matching.inject_expectation_signatures
                if s.type == "parent_process_name"
            )
            + ".exe"
            if o.matching
            else "explorer.exe"
        )
    )
    actor_process_command_line = factory.Faker(
        "openaev_implant_command_line",
        inject_id=factory.SelfAttribute("..inject_id"),
        agent_id=factory.SelfAttribute("..agent_id"),
    )
    mitre_technique_ids = factory.List([factory.Faker("mitre_attack_technique_id")])
