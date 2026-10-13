import hashlib
import ipaddress
import re
from datetime import datetime

import pytest

from faker_cti.openaev import (
    CLOUD_PROVIDERS,
    COLLECTORS,
    EXECUTION_ACTIONS,
    EXECUTION_STATUSES,
    PLATFORMS,
    SECURITY_PLATFORM_TYPES,
    SIGNATURE_TYPES,
)

UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# Regex used by the OpenAEV SIEM collectors (splunk-es, elastic, qradar...) parent process parser
IMPLANT_PATTERN = rf"oaev-implant-({UUID})-agent-({UUID})"


def test_implant_name_matches_collector_parser(fake):
    match = re.fullmatch(IMPLANT_PATTERN, fake.openaev_implant_name())
    assert match
    name = fake.openaev_implant_name("i" * 36, "a" * 36, extension="exe")
    assert name == f"oaev-implant-{'i' * 36}-agent-{'a' * 36}.exe"


def test_implant_command_line(fake):
    inject_id, agent_id = fake.openaev_id(), fake.openaev_id()
    command_line = fake.openaev_implant_command_line(inject_id, agent_id)
    match = re.search(IMPLANT_PATTERN, command_line)
    assert match.groups() == (inject_id, agent_id)
    assert f"--inject-id {inject_id}" in command_line
    assert re.search(IMPLANT_PATTERN, fake.openaev_implant_command_line())


def test_ai_marker_matches_pyoaev_algorithm(fake):
    expected = "oaev" + hashlib.sha256(b"inject:agent").hexdigest()[:16]
    assert fake.openaev_ai_marker("inject", "agent") == expected
    assert re.fullmatch(r"oaev[0-9a-f]{16}", fake.openaev_ai_marker())


def test_collector_id(fake):
    assert re.fullmatch(rf"splunk-es--{UUID}", fake.openaev_collector_id("splunk-es"))
    assert re.fullmatch(rf"[a-z-]+--{UUID}", fake.openaev_collector_id())


def test_enums(fake):
    assert fake.openaev_signature_type() in SIGNATURE_TYPES
    assert fake.openaev_execution_status() in EXECUTION_STATUSES
    assert fake.openaev_execution_action() in EXECUTION_ACTIONS
    assert fake.openaev_security_platform_type() in SECURITY_PLATFORM_TYPES
    assert fake.openaev_cloud_provider() in CLOUD_PROVIDERS
    assert fake.openaev_platform() in PLATFORMS
    assert fake.openaev_expectation_type() in {"DETECTION", "PREVENTION", "VULNERABILITY"}


@pytest.mark.parametrize("signature_type", SIGNATURE_TYPES)
def test_every_signature_type_has_a_value(fake, signature_type):
    signature = fake.openaev_expectation_signature(signature_type)
    assert signature["type"] == signature_type
    assert isinstance(signature["value"], str) and signature["value"]


def test_signature_values_are_typed(fake):
    assert re.fullmatch(IMPLANT_PATTERN, fake.openaev_signature_value("parent_process_name"))
    assert ipaddress.ip_address(fake.openaev_signature_value("source_ipv4_address")).is_private
    assert ipaddress.ip_address(fake.openaev_signature_value("target_ipv6_address")).version == 6
    datetime.fromisoformat(fake.openaev_signature_value("start_date"))
    assert fake.openaev_expectation_signature("hostname", "h") == {"type": "hostname", "value": "h"}
    with pytest.raises(ValueError):
        fake.openaev_signature_value("nope")


def test_expectation_default_signatures(fake):
    expectation = fake.openaev_expectation(inject_id="I", agent_id="A")
    signatures = {s["type"]: s["value"] for s in expectation["inject_expectation_signatures"]}
    assert expectation["inject_expectation_type"] in {"DETECTION", "PREVENTION"}
    assert signatures["parent_process_name"] == "oaev-implant-I-agent-A"
    start = datetime.fromisoformat(signatures["start_date"])
    end = datetime.fromisoformat(signatures["end_date"])
    assert start < end
    assert expectation["inject_expectation_results"] == []


def test_expectation_custom_signatures(fake):
    expectation = fake.openaev_expectation("DETECTION", ["source_ipv4_address", "hostname"])
    assert [s["type"] for s in expectation["inject_expectation_signatures"]] == [
        "source_ipv4_address",
        "hostname",
    ]


@pytest.mark.parametrize(
    ("expectation_type", "success", "label"),
    [
        ("DETECTION", True, "Detected"),
        ("DETECTION", False, "Not Detected"),
        ("PREVENTION", True, "Prevented"),
        ("PREVENTION", False, "Not Prevented"),
    ],
)
def test_expectation_result(fake, expectation_type, success, label):
    result = fake.openaev_expectation_result(expectation_type, success, collector_id="c")
    assert result == {
        "collector_id": "c",
        "result": label,
        "is_success": success,
        "metadata": {"alertId": result["metadata"]["alertId"]},
    }


def test_expectation_result_rejects_vulnerability(fake):
    with pytest.raises(ValueError):
        fake.openaev_expectation_result("VULNERABILITY")


def test_expectation_trace(fake):
    trace = fake.openaev_expectation_trace("e", "c")
    assert trace["inject_expectation_trace_expectation"] == "e"
    assert trace["inject_expectation_trace_source_id"] == "c"
    assert trace["inject_expectation_trace_alert_link"].startswith("https://")


@pytest.mark.parametrize("platform", list(PLATFORMS))
def test_endpoint(fake, platform):
    endpoint = fake.openaev_endpoint(platform)
    assert endpoint["endpoint_platform"] == platform
    assert endpoint["endpoint_arch"] in PLATFORMS[platform]
    assert endpoint["asset_agents"][0]["agent_id"]
    assert ipaddress.ip_address(endpoint["asset_ips"][0]).is_private
    assert fake.openaev_endpoint(with_agent=False)["asset_agents"] == []


def test_injection_message(fake):
    message = fake.openaev_injection_message(
        contract_id="contract", expectation_types=["DETECTION"], content={"ports": "22"}
    )
    injection = message["injection"]
    assert injection["inject_injector_contract"]["injector_contract_id"] == "contract"
    assert injection["inject_content"]["expectations"] == [{"expectation_type": "DETECTION"}]
    assert injection["inject_content"]["ports"] == "22"
    assert injection["inject_content"]["target_selector"] == "assets"
    assert len(message["assets"]) == 1
    assert fake.openaev_injection_message(assets=[])["assets"] == []


def test_execution_callback(fake):
    callback = fake.openaev_execution_callback("INFO", "command_execution", "asset-1")
    assert callback["execution_status"] == "INFO"
    assert callback["execution_action"] == "command_execution"
    assert callback["execution_context_identifiers"] == ["asset-1"]


@pytest.mark.parametrize("slug", [c[0] for c in COLLECTORS])
def test_collector_env(fake, slug):
    env = fake.openaev_collector_env(slug)
    assert env["COLLECTOR_ID"].startswith(f"{slug}--")
    assert env["COLLECTOR_TYPE"] == f"openaev_{slug.replace('-', '_')}"
    assert {"OPENAEV_URL", "OPENAEV_TOKEN", "COLLECTOR_PERIOD"} <= env.keys()


def test_injector_env(fake):
    env = fake.openaev_injector_env("http-query")
    assert env["INJECTOR_TYPE"] == "openaev_http_query"
    assert env["INJECTOR_NAME"] == "Http Query"
    assert fake.openaev_injector_env()["INJECTOR_TYPE"].startswith("openaev_")
