"""STIX output is validated against the reference ``stix2`` implementation."""

import re

import pytest
import stix2

from faker_cti.data.stix import PAP_MARKINGS, STIX_CYBER_OBSERVABLE_TYPES, TLP_MARKINGS

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def test_random_stix_id(fake):
    assert re.fullmatch(rf"indicator--{UUID}", fake.stix_id("indicator"))
    assert re.fullmatch(rf"[a-z0-9-]+--{UUID}", fake.stix_id())
    assert fake.stix_id("malware") != fake.stix_id("malware")


@pytest.mark.parametrize(
    ("stix_type", "properties", "stix2_object"),
    [
        ("ipv4-addr", {"value": "1.2.3.4"}, stix2.IPv4Address(value="1.2.3.4")),
        ("ipv6-addr", {"value": "2001:db8::1"}, stix2.IPv6Address(value="2001:db8::1")),
        ("domain-name", {"value": "example.com"}, stix2.DomainName(value="example.com")),
        ("url", {"value": "https://example.com/a"}, stix2.URL(value="https://example.com/a")),
        ("email-addr", {"value": "a@example.com"}, stix2.EmailAddress(value="a@example.com")),
        ("mac-addr", {"value": "00:11:22:33:44:55"}, stix2.MACAddress(value="00:11:22:33:44:55")),
        ("autonomous-system", {"number": 64512}, stix2.AutonomousSystem(number=64512)),
        ("mutex", {"name": "Global\\abc"}, stix2.Mutex(name="Global\\abc")),
        (
            "file",
            {"hashes": {"SHA-256": "a" * 64, "MD5": "b" * 32}, "name": "x.exe"},
            stix2.File(hashes={"SHA-256": "a" * 64, "MD5": "b" * 32}, name="x.exe"),
        ),
        (
            "file",
            {"hashes": {"SSDEEP": "3:a:b"}, "name": None},
            stix2.File(hashes={"SSDEEP": "3:a:b"}),
        ),
    ],
)
def test_deterministic_ids_match_stix2(fake, stix_type, properties, stix2_object):
    assert fake.stix_id(stix_type, **properties) == stix2_object.id


def test_stix_type_categories(fake):
    assert fake.stix_type("sco") in STIX_CYBER_OBSERVABLE_TYPES
    assert fake.stix_type("sdo") not in STIX_CYBER_OBSERVABLE_TYPES
    with pytest.raises(ValueError):
        fake.stix_type("sro")


def test_stix_timestamp_is_parsed_by_stix2(fake):
    timestamp = fake.stix_timestamp()
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", timestamp)
    stix2.Identity(name="x", created=timestamp, modified=timestamp)


@pytest.mark.parametrize(
    ("level", "stix2_marking"),
    [
        ("TLP:WHITE", stix2.TLP_WHITE),
        ("clear", stix2.TLP_WHITE),
        ("green", stix2.TLP_GREEN),
        ("TLP:AMBER", stix2.TLP_AMBER),
        ("tlp:red", stix2.TLP_RED),
    ],
)
def test_tlp_ids_match_stix2(fake, level, stix2_marking):
    assert fake.tlp_marking_id(level) == stix2_marking.id


def test_tlp_amber_strict_and_random(fake):
    assert fake.tlp_marking_id("amber+strict").endswith("826578e1-40ad-459f-bc73-ede076f81f37")
    assert fake.tlp_marking_id() in TLP_MARKINGS.values()
    assert fake.tlp_level() != "TLP:WHITE"


def test_pap_ids_follow_opencti_generation(fake):
    for level, marking_id in PAP_MARKINGS.items():
        assert fake.stix_id("marking-definition", definition_type="PAP", definition=level) == (
            marking_id
        )
    assert fake.pap_marking_id("amber") == PAP_MARKINGS["PAP:AMBER"]
    assert fake.pap_marking_id() in PAP_MARKINGS.values()
    assert fake.pap_level() in PAP_MARKINGS


def test_unknown_marking_level(fake):
    with pytest.raises(ValueError, match="TLP:PURPLE"):
        fake.tlp_marking_id("purple")


def test_marking_definition_object(fake):
    marking = fake.stix_marking_definition("red")
    assert marking["id"] == stix2.TLP_RED.id
    assert marking["x_opencti_definition"] == "TLP:RED"
    stix2.parse(marking, allow_custom=True)


@pytest.mark.parametrize(
    "stix_type",
    [
        "ipv4-addr",
        "ipv6-addr",
        "domain-name",
        "url",
        "email-addr",
        "mac-addr",
        "file",
        "autonomous-system",
        "mutex",
        None,
    ],
)
def test_observables_are_valid_stix(fake, stix_type):
    observable = fake.stix_observable(stix_type, x_opencti_score=50)
    parsed = stix2.parse(observable, allow_custom=True)
    assert parsed.id == observable["id"]
    assert observable["x_opencti_score"] == 50


def test_observable_with_explicit_value(fake):
    assert (
        fake.stix_observable("ipv4-addr", "1.2.3.4")["id"] == stix2.IPv4Address(value="1.2.3.4").id
    )
    assert fake.stix_observable("autonomous-system", "64600")["number"] == 64600
    assert fake.stix_observable("mutex", "m")["name"] == "m"
    assert fake.stix_observable("file", "evil.exe")["name"] == "evil.exe"


def test_hostname_is_an_opencti_custom_observable(fake):
    observable = fake.stix_observable("hostname")
    assert observable["id"] == fake.stix_id("hostname", value=observable["value"])


def test_observable_value_rejects_non_value_types(fake):
    with pytest.raises(ValueError):
        fake.stix_observable_value("file")


@pytest.mark.parametrize("stix_type", ["ipv4-addr", "domain-name", "url", "file", None])
def test_patterns_are_valid(fake, stix_type):
    pattern = fake.stix_pattern(stix_type)
    stix2.Indicator(pattern=pattern, pattern_type="stix")


def test_pattern_with_value(fake):
    assert fake.stix_pattern("ipv4-addr", "1.2.3.4") == "[ipv4-addr:value = '1.2.3.4']"
    assert fake.stix_pattern("file", "a" * 32) in {
        f"[file:hashes.{key} = '{'a' * 32}']" for key in ("MD5", "'SHA-1'", "'SHA-256'")
    }


def test_indicator_relationship_and_bundle_are_valid_stix(fake):
    indicator = fake.stix_indicator("domain-name", "c2.example.com", confidence=90)
    assert indicator["name"] == "c2.example.com"
    assert indicator["confidence"] == 90
    assert indicator["x_opencti_main_observable_type"] == "Domain-Name"
    relationship = fake.stix_relationship(indicator["id"], relationship_type="indicates")
    bundle = fake.stix_bundle([indicator, relationship])
    parsed = stix2.parse(bundle, allow_custom=True)
    assert len(parsed.objects) == 2
    stix2.parse(fake.stix_bundle(), allow_custom=True)


def test_external_references(fake):
    for _ in range(20):
        reference = fake.stix_external_reference()
        assert reference["source_name"] and reference["url"].startswith(("http://", "https://"))
    assert fake.stix_external_reference("VirusTotal")["source_name"] == "VirusTotal"


def test_kill_chain_phase(fake):
    phase = fake.stix_kill_chain_phase()
    assert phase["kill_chain_name"] == "mitre-attack"
    stix2.KillChainPhase(**phase)


SDO_FORMATTERS = [
    "stix_attack_pattern",
    "stix_malware",
    "stix_tool",
    "stix_intrusion_set",
    "stix_threat_actor",
    "stix_vulnerability",
    "stix_identity",
    "stix_location",
    "stix_report",
]


@pytest.mark.parametrize("formatter", SDO_FORMATTERS)
def test_domain_objects_are_valid_stix(fake, formatter):
    sdo = getattr(fake, formatter)(confidence=80)
    parsed = stix2.parse(sdo, allow_custom=True)
    assert parsed.id == sdo["id"]
    assert sdo["confidence"] == 80


@pytest.mark.parametrize("formatter", SDO_FORMATTERS)
def test_domain_object_ids_are_deterministic(fake, formatter):
    """Same name => same id, which is what makes OpenCTI deduplicate entities."""
    first = getattr(fake, formatter)()
    kwargs = {
        "stix_attack_pattern": {"technique_id": first.get("x_mitre_id")},
        "stix_location": {"country_code": first.get("country")},
        "stix_identity": {"name": first["name"], "identity_class": first.get("identity_class")},
        "stix_report": {"name": first["name"]},
    }.get(formatter, {"name": first["name"]})
    second = getattr(fake, formatter)(**kwargs)
    if formatter != "stix_report":  # report ids also depend on the published date
        assert first["id"] == second["id"]


def test_domain_object_arguments(fake):
    assert fake.stix_attack_pattern("T1059.001")["name"] == "PowerShell"
    assert fake.stix_location("fr")["name"] == "France"
    assert fake.stix_identity(identity_class="class")["identity_class"] == "class"
    assert fake.stix_intrusion_set("Custom Set")["aliases"] == []
    report = fake.stix_report(object_refs=["malware--x"])
    assert report["object_refs"] == ["malware--x"]
    with pytest.raises(ValueError):
        fake.stix_attack_pattern("T0000")
    with pytest.raises(ValueError):
        fake.stix_location("XX")


def test_ids_match_pycti(fake):
    pycti = pytest.importorskip("pycti")
    assert fake.stix_malware("Emotet")["id"] == pycti.Malware.generate_id("Emotet")
    assert fake.stix_tool(" Mimikatz ")["id"] == pycti.Tool.generate_id("Mimikatz")
    assert fake.stix_intrusion_set("APT28")["id"] == pycti.IntrusionSet.generate_id("APT28")
    assert fake.stix_threat_actor("APT28")["id"] == pycti.ThreatActorGroup.generate_id("APT28")
    assert fake.stix_vulnerability("CVE-2021-44228")["id"] == pycti.Vulnerability.generate_id(
        "CVE-2021-44228"
    )
    assert fake.stix_attack_pattern("T1059")["id"] == pycti.AttackPattern.generate_id(
        "Command and Scripting Interpreter", "T1059"
    )
    assert fake.stix_identity("Filigran")["id"] == pycti.Identity.generate_id(
        "Filigran", "organization"
    )
    assert fake.stix_location("FR")["id"] == pycti.Location.generate_id("France", "Country")
    report = fake.stix_report(name="Weekly")
    assert report["id"] == pycti.Report.generate_id("Weekly", report["published"])
    indicator = fake.stix_indicator("ipv4-addr", "1.2.3.4")
    assert indicator["id"] == pycti.Indicator.generate_id(indicator["pattern"])
    relationship = fake.stix_relationship("malware--a", "intrusion-set--b", "uses")
    assert relationship["id"] == pycti.StixCoreRelationship.generate_id(
        "uses", "malware--a", "intrusion-set--b"
    )
    start, stop = "2024-01-01T00:00:00.000Z", "2024-02-01T00:00:00.000Z"
    for kwargs in (
        {"start_time": start},
        {"start_time": start, "stop_time": stop},
        {"stop_time": stop},
    ):
        relationship = fake.stix_relationship("malware--a", "intrusion-set--b", "uses", **kwargs)
        assert relationship["id"] == pycti.StixCoreRelationship.generate_id(
            "uses", "malware--a", "intrusion-set--b", **kwargs
        )
    for level in ("PAP:CLEAR", "PAP:GREEN", "PAP:AMBER", "PAP:RED"):
        assert fake.pap_marking_id(level) == pycti.MarkingDefinition.generate_id("PAP", level)
    for level in ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"):
        assert fake.tlp_marking_id(level) == pycti.MarkingDefinition.generate_id("TLP", level)


def test_relationship_refs_drive_the_id(fake):
    first = fake.stix_relationship("malware--a", "intrusion-set--b", "uses")
    assert (first["source_ref"], first["target_ref"]) == ("malware--a", "intrusion-set--b")
    assert first["id"] == fake.stix_relationship("malware--a", "intrusion-set--b", "uses")["id"]
    assert first["id"] != fake.stix_relationship("malware--a", "intrusion-set--c", "uses")["id"]
    timed = fake.stix_relationship(
        "malware--a", "intrusion-set--b", "uses", start_time="2024-01-01T00:00:00.000Z"
    )
    assert timed["start_time"] == "2024-01-01T00:00:00.000Z"
    assert timed["id"] != first["id"]
    stix2.parse(
        fake.stix_relationship(
            fake.stix_id("malware"),
            fake.stix_id("intrusion-set"),
            "uses",
            start_time="2024-01-01T00:00:00.000Z",
            stop_time="2024-02-01T00:00:00.000Z",
        )
    )
