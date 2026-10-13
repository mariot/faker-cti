from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any

from faker_cti._utils import random_datetime, random_hex, random_uuid4
from faker_cti.threat_intel import ThreatIntelProvider

# Values mirror the enums of pyoaev (``pyoaev.signatures.types`` and ``pyoaev.asset_types``)
SIGNATURE_TYPES = (
    "process_name",
    "parent_process_name",
    "command_line",
    "ipv4_address",
    "ipv6_address",
    "source_ipv4_address",
    "source_ipv6_address",
    "target_ipv4_address",
    "target_ipv6_address",
    "hostname",
    "target_hostname_address",
    "start_date",
    "end_date",
    "cloud_provider",
    "cloud_account_id",
    "cloud_region",
    "target_service",
    "query",
    "url_hash",
    "file_name",
    "file_hash",
    "source_email",
    "target_email",
    "email_custom_header",
    "ai_request_marker",
    "ai_target_endpoint",
)

EXPECTATION_TYPES = ("DETECTION", "PREVENTION", "VULNERABILITY")

EXPECTATION_RESULTS = {
    "DETECTION": ("Detected", "Not Detected"),
    "PREVENTION": ("Prevented", "Not Prevented"),
}

EXECUTION_STATUSES = (
    "EXECUTED",
    "EXECUTED_WITH_CLEANUP_FAILURE",
    "WARNING",
    "ACCESS_DENIED",
    "ERROR",
    "COMMAND_NOT_FOUND",
    "COMMAND_CANNOT_BE_EXECUTED",
    "PREREQUISITE_FAILED",
    "INVALID_USAGE",
    "TIMEOUT",
    "INTERRUPTED",
    "ASSET_AGENTLESS",
    "AGENT_INACTIVE",
    "AGENT_OVERLOADED",
    "INFO",
    "PARTIAL",
    "MAYBE_PREVENTED",
    "MAYBE_PARTIAL_PREVENTED",
)

EXECUTION_ACTIONS = (
    "prerequisite_check",
    "prerequisite_execution",
    "cleanup_execution",
    "command_execution",
    "dns_resolution",
    "file_execution",
    "file_drop",
    "data",
    "complete",
)

SECURITY_PLATFORM_TYPES = (
    "EDR",
    "XDR",
    "SIEM",
    "SOAR",
    "NDR",
    "ISPM",
    "LLM_FIREWALL",
    "AI_GATEWAY",
)

CLOUD_PROVIDERS = ("AWS", "AZURE", "GCP", "OCI", "ALIBABA", "KUBERNETES", "OTHER")

CLOUD_REGIONS = {
    "AWS": ("us-east-1", "eu-west-1", "eu-west-3", "ap-southeast-2"),
    "AZURE": ("westeurope", "francecentral", "eastus", "japaneast"),
    "GCP": ("europe-west1", "us-central1", "asia-east1"),
}

PLATFORMS = {
    "Windows": ("x86_64", "arm64"),
    "Linux": ("x86_64", "arm64"),
    "MacOS": ("arm64", "x86_64"),
}

# (collector type slug, display name, security platform type)
COLLECTORS = (
    ("crowdstrike", "CrowdStrike Endpoint Security", "EDR"),
    ("microsoft-defender", "Microsoft Defender", "EDR"),
    ("sentinelone", "SentinelOne", "EDR"),
    ("palo-alto-cortex-xdr", "Palo Alto Cortex XDR", "XDR"),
    ("palo-alto-cortex-xsoar", "Palo Alto Cortex XSOAR", "SOAR"),
    ("splunk-es", "Splunk ES", "SIEM"),
    ("elastic", "Elastic Security", "SIEM"),
    ("qradar", "IBM QRadar", "SIEM"),
    ("netwitness", "NetWitness", "SIEM"),
    ("logrhythm", "LogRhythm", "SIEM"),
)


class OpenAEVProvider(ThreatIntelProvider):
    """Data exchanged between OpenAEV, its agents, injectors and collectors (pyoaev)."""

    __provider__ = "openaev"

    # -- identifiers ----------------------------------------------------------------------

    def openaev_id(self) -> str:
        """Platform id (inject, agent, asset, expectation...): a UUIDv4."""
        return random_uuid4(self.generator.random)

    def openaev_collector_id(self, slug: str | None = None) -> str:
        """Collector id as built by collectors, e.g. ``splunk-es--<uuid>``."""
        slug = slug or self.random_element(COLLECTORS)[0]
        return f"{slug}--{self.openaev_id()}"

    def openaev_implant_name(
        self,
        inject_id: str | None = None,
        agent_id: str | None = None,
        extension: str | None = None,
    ) -> str:
        """Process name of an OpenAEV implant: ``oaev-implant-<inject id>-agent-<agent id>``.

        This is what EDR/SIEM collectors match ``parent_process_name`` signatures against.
        """
        name = (
            f"oaev-implant-{inject_id or self.openaev_id()}-agent-{agent_id or self.openaev_id()}"
        )
        return f"{name}.{extension}" if extension else name

    def openaev_implant_command_line(
        self, inject_id: str | None = None, agent_id: str | None = None
    ) -> str:
        """Command line of a Windows implant, as reported in EDR process evidence."""
        inject_id = inject_id or self.openaev_id()
        agent_id = agent_id or self.openaev_id()
        return (
            f'"{self.openaev_implant_name(inject_id, agent_id, "exe")}" '
            f"--uri https://openaev.example.com --token {self.openaev_id()} "
            f"--unsecured-certificate false --with-proxy false "
            f"--agent-id {agent_id} --inject-id {inject_id}"
        )

    def openaev_ai_marker(self, inject_id: str | None = None, agent_id: str = "") -> str:
        """Canary marker of AI red-team injects.

        Same algorithm as ``pyoaev.signatures.ai_marker.build_marker``.
        """
        seed = f"{inject_id or self.openaev_id()}:{agent_id}".encode()
        return "oaev" + hashlib.sha256(seed).hexdigest()[:16]

    # -- enums ----------------------------------------------------------------------------

    def openaev_signature_type(self) -> str:
        return self.random_element(SIGNATURE_TYPES)

    def openaev_expectation_type(self) -> str:
        return self.random_element(EXPECTATION_TYPES)

    def openaev_execution_status(self) -> str:
        return self.random_element(EXECUTION_STATUSES)

    def openaev_execution_action(self) -> str:
        return self.random_element(EXECUTION_ACTIONS)

    def openaev_security_platform_type(self) -> str:
        return self.random_element(SECURITY_PLATFORM_TYPES)

    def openaev_cloud_provider(self) -> str:
        return self.random_element(CLOUD_PROVIDERS)

    def openaev_platform(self) -> str:
        """Endpoint platform: ``Windows``, ``Linux`` or ``MacOS``."""
        return self.random_element(tuple(PLATFORMS))

    # -- expectations ---------------------------------------------------------------------

    def openaev_signature_value(self, signature_type: str) -> str:
        """Plausible value for a given expectation signature type."""
        rand = self.generator.random
        values = {
            "process_name": lambda: self.random_element(
                ("powershell.exe", "cmd.exe", "rundll32.exe", "bash", "sh", "python3")
            ),
            "parent_process_name": self.openaev_implant_name,
            "command_line": lambda: self.random_element(
                (
                    '"cmd" /V /C setlocal & net share & exit /b errorlevel',
                    "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command whoami /all",
                    "/bin/sh -c 'uname -a && id'",
                )
            ),
            "ipv4_address": self.generator.ipv4_private,
            "source_ipv4_address": self.generator.ipv4_private,
            "target_ipv4_address": self.generator.ipv4_public,
            "ipv6_address": self.generator.ipv6,
            "source_ipv6_address": self.generator.ipv6,
            "target_ipv6_address": self.generator.ipv6,
            "hostname": self.generator.hostname,
            "target_hostname_address": self.generator.hostname,
            "start_date": lambda: random_datetime(rand).isoformat(),
            "end_date": lambda: random_datetime(rand).isoformat(),
            "cloud_provider": self.openaev_cloud_provider,
            "cloud_account_id": lambda: self.numerify("############"),
            "cloud_region": lambda: self.random_element(CLOUD_REGIONS["AWS"]),
            "target_service": lambda: self.random_element(("s3", "iam", "ec2", "lambda", "kms")),
            "query": lambda: self.random_element(
                ("SELECT * FROM users WHERE '1'='1'", "nslookup example.com")
            ),
            "url_hash": lambda: random_hex(rand, 64),
            "file_name": lambda: self.generator.file_name(extension="exe"),
            "file_hash": lambda: random_hex(rand, 64),
            "source_email": self.generator.email,
            "target_email": self.generator.company_email,
            "email_custom_header": lambda: f"X-OAEV-Inject: {self.openaev_id()}",
            "ai_request_marker": self.openaev_ai_marker,
            "ai_target_endpoint": lambda: "https://llm.example.com/v1/chat/completions",
        }
        if signature_type not in values:
            raise ValueError(f"Unknown signature type {signature_type!r}")
        return values[signature_type]()

    def openaev_expectation_signature(
        self, signature_type: str | None = None, value: str | None = None
    ) -> dict[str, str]:
        """``{"type": ..., "value": ...}`` as found in ``inject_expectation_signatures``."""
        signature_type = signature_type or self.openaev_signature_type()
        return {
            "type": signature_type,
            "value": value if value is not None else self.openaev_signature_value(signature_type),
        }

    def openaev_expectation(
        self,
        expectation_type: str | None = None,
        signature_types: tuple[str, ...] | list[str] | None = None,
        inject_id: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Inject expectation as fetched by collectors.

        Default signatures are those emitted for agent-based injects: the implant as
        ``parent_process_name`` plus the ``start_date``/``end_date`` window. The implant
        name embeds ``inject_id`` and ``agent_id`` so tests can assert on them.
        """
        expectation_type = expectation_type or self.random_element(("DETECTION", "PREVENTION"))
        signature_types = signature_types or ("parent_process_name", "start_date", "end_date")
        inject_id = inject_id or self.openaev_id()
        agent_id = agent_id or self.openaev_id()
        start = random_datetime(self.generator.random)
        duration = timedelta(minutes=self.generator.random.randint(5, 120))
        overrides = {
            "parent_process_name": self.openaev_implant_name(inject_id, agent_id),
            "start_date": start.isoformat(),
            "end_date": (start + duration).isoformat(),
        }
        return {
            "inject_expectation_id": self.openaev_id(),
            "inject_expectation_type": expectation_type,
            "inject_expectation_inject": inject_id,
            "inject_expectation_agent": agent_id,
            "inject_expectation_signatures": [
                self.openaev_expectation_signature(t, overrides.get(t)) for t in signature_types
            ],
            "inject_expectation_results": [],
        }

    def openaev_expectation_result(
        self,
        expectation_type: str | None = None,
        is_success: bool | None = None,
        collector_id: str | None = None,
    ) -> dict[str, Any]:
        """Payload sent by a collector through ``inject_expectation.update``."""
        expectation_type = expectation_type or self.random_element(("DETECTION", "PREVENTION"))
        if expectation_type not in EXPECTATION_RESULTS:
            raise ValueError(f"Collectors only report {sorted(EXPECTATION_RESULTS)} results")
        is_success = self.generator.pybool() if is_success is None else is_success
        success_label, failure_label = EXPECTATION_RESULTS[expectation_type]
        return {
            "collector_id": collector_id or self.openaev_collector_id(),
            "result": success_label if is_success else failure_label,
            "is_success": is_success,
            "metadata": {"alertId": self.openaev_id()},
        }

    def openaev_expectation_trace(
        self, expectation_id: str | None = None, collector_id: str | None = None
    ) -> dict[str, str]:
        """Trace linking an expectation to the security alert that matched it."""
        alert_id = self.openaev_id()
        return {
            "inject_expectation_trace_expectation": expectation_id or self.openaev_id(),
            "inject_expectation_trace_source_id": collector_id or self.openaev_collector_id(),
            "inject_expectation_trace_alert_name": f"{self.malware_family()} activity detected",
            "inject_expectation_trace_alert_link": f"https://security.example.com/alerts/{alert_id}",
            "inject_expectation_trace_date": random_datetime(self.generator.random).isoformat(),
        }

    # -- endpoints, injections and callbacks ----------------------------------------------

    def openaev_endpoint(
        self,
        platform: str | None = None,
        with_agent: bool = True,
    ) -> dict[str, Any]:
        """Endpoint asset as found in an injection's ``assets`` list."""
        platform = platform or self.openaev_platform()
        hostname = self.generator.hostname(0)
        agents = (
            [
                {
                    "agent_id": self.openaev_id(),
                    "agent_executed_by_user": "NT AUTHORITY\\SYSTEM"
                    if platform == "Windows"
                    else "root",
                }
            ]
            if with_agent
            else []
        )
        return {
            "asset_id": self.openaev_id(),
            "asset_type": "Endpoint",
            "asset_name": hostname,
            "asset_hostname": hostname.lower(),
            "asset_description": self.generator.sentence(),
            "asset_ips": [self.generator.ipv4_private()],
            "asset_seen_ip": self.generator.ipv4_public(),
            "asset_tags": [],
            "asset_agents": agents,
            "endpoint_platform": platform,
            "endpoint_arch": self.random_element(PLATFORMS[platform]),
            "endpoint_mac_addresses": [self.generator.mac_address()],
        }

    def openaev_injection_message(
        self,
        contract_id: str | None = None,
        assets: list[dict[str, Any]] | None = None,
        expectation_types: tuple[str, ...] | list[str] | None = None,
        content: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Message consumed by injectors from RabbitMQ."""
        assets = assets if assets is not None else [self.openaev_endpoint()]
        expectation_types = expectation_types or ("DETECTION", "PREVENTION")
        inject_content = {
            "target_selector": "assets",
            "target_property_selector": "Automatic",
            "expectations": [{"expectation_type": t} for t in expectation_types],
            **(content or {}),
        }
        return {
            "injection": {
                "inject_id": self.openaev_id(),
                "inject_title": self.generator.catch_phrase(),
                "inject_injector_contract": {
                    "injector_contract_id": contract_id or self.openaev_id(),
                    "convertedContent": {},
                },
                "inject_content": inject_content,
                "inject_documents": [],
            },
            "assets": assets,
            "assetGroups": [],
        }

    def openaev_execution_callback(
        self, status: str | None = None, action: str | None = None, asset_id: str | None = None
    ) -> dict[str, Any]:
        """Payload posted by injectors through ``inject.execution_callback``."""
        return {
            "execution_message": self.generator.sentence(),
            "execution_status": status or self.random_element(("SUCCESS", "INFO", "ERROR")),
            "execution_duration": self.generator.random.randint(100, 120_000),
            "execution_action": action or self.openaev_execution_action(),
            "execution_context_identifiers": [asset_id or self.openaev_id()],
        }

    # -- configuration --------------------------------------------------------------------

    def openaev_collector_env(self, slug: str | None = None) -> dict[str, str]:
        """Environment variables of a collector."""
        slug, name, _ = (
            next(c for c in COLLECTORS if c[0] == slug) if slug else self.random_element(COLLECTORS)
        )
        return {
            "OPENAEV_URL": "http://localhost:8080",
            "OPENAEV_TOKEN": self.openaev_id(),
            "COLLECTOR_ID": self.openaev_collector_id(slug),
            "COLLECTOR_NAME": name,
            "COLLECTOR_TYPE": f"openaev_{slug.replace('-', '_')}",
            "COLLECTOR_PERIOD": self.random_element(("PT30S", "PT1M", "PT5M", "PT2H")),
            "COLLECTOR_LOG_LEVEL": self.random_element(("debug", "info", "warning", "error")),
        }

    def openaev_injector_env(self, slug: str | None = None) -> dict[str, str]:
        """Environment variables of an injector."""
        slug = slug or self.random_element(("nmap", "nuclei", "http-query", "prowler", "shodan"))
        return {
            "OPENAEV_URL": "http://localhost:8080",
            "OPENAEV_TOKEN": self.openaev_id(),
            "INJECTOR_ID": self.openaev_id(),
            "INJECTOR_NAME": slug.replace("-", " ").title(),
            "INJECTOR_TYPE": f"openaev_{slug.replace('-', '_')}",
            "INJECTOR_LOG_LEVEL": self.random_element(("debug", "info", "warning", "error")),
        }
