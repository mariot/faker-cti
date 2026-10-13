# faker-cti

[Faker](https://github.com/joke2k/faker) providers for **cyber threat intelligence** test data:
STIX 2.1 objects and identifiers, TLP/PAP markings, MITRE ATT&CK, vulnerabilities, threat
names, plus the payloads exchanged by [OpenCTI](https://github.com/OpenCTI-Platform/opencti)
connectors and [OpenAEV](https://github.com/OpenAEV-Platform/openaev) injectors/collectors.

Everything is built for unit tests with [factory_boy](https://factoryboy.readthedocs.io):
values are reproducible with `Faker.seed()` / `factory.random.reseed_random()`, and ids are
**the ids the real tools compute**. Deterministic STIX ids match the `stix2` library, and
domain-object ids match `pycti` `generate_id`, so an id in a fixture is the id OpenCTI
would store.

faker-cti does not reimplement anything Faker already has. IP addresses, domains, URLs,
emails, host names, MAC addresses and MD5/SHA hashes come from Faker's built-in providers.

```python
>>> from faker import Faker
>>> from faker_cti import CtiProvider
>>> fake = Faker()
>>> fake.add_provider(CtiProvider)

>>> fake.stix_id("ipv4-addr", value="1.2.3.4")        # same as stix2.IPv4Address(value=...).id
'ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4'
>>> fake.tlp_marking_id("amber+strict")
'marking-definition--826578e1-40ad-459f-bc73-ede076f81f37'
>>> fake.stix_pattern("domain-name")
"[domain-name:value = 'jones.com']"
>>> fake.mitre_attack_technique()
{'external_id': 'T1059.001', 'name': 'PowerShell', 'phase_name': 'execution',
 'url': 'https://attack.mitre.org/techniques/T1059/001'}
>>> fake.openaev_implant_name()
'oaev-implant-bfe4440e-60fc-47fa-bf8b-1baa47158a7e-agent-309944e2-f5b5-4934-8106-bb058f332483'
```

## Installation

```bash
pip install faker-cti        # or: uv add --dev faker-cti
```

Requires Python 3.10+ and Faker 20+. No other runtime dependency (`stix2` and `pycti` are
only used in this project's own tests to check the output).

## Providers

You can register `CtiProvider` to get every formatter, or register only the layer you need.
Each provider includes the ones before it:

| Provider              | Adds                                                                                 |
|-----------------------|--------------------------------------------------------------------------------------|
| `ThreatIntelProvider` | hashes (STIX-keyed dicts, ssdeep, TLSH), ASN, CVE/CWE/CPE, MITRE ATT&CK, threat names |
| `StixProvider`        | STIX ids, timestamps, vocabularies, markings, patterns, SCOs, SDOs, SROs, bundles     |
| `OpenCTIProvider`     | enrichment messages, connector config/env, markings, work ids, scores                 |
| `OpenAEVProvider`     | implant names, expectations and signatures, results, endpoints, injection messages    |
| `CtiProvider`         | all of the above                                                                     |

`Faker(includes=["faker_cti"])` and the Faker CLI (`faker -i faker_cti stix_id`) also work.

### Threat intelligence

| Formatter | Example |
|---|---|
| `file_hashes(algorithms=None)` | `{"MD5": "…", "SHA-1": "…", "SHA-256": "…"}`; also `SHA-512`, `SSDEEP`, `TLSH` |
| `ssdeep()` / `tlsh()` | `384:dC4/DSDC6Lc1mx…:A2h9Uz0+T1…` / `T1A81AA42B…` |
| `asn()` / `autonomous_system_number()` | `AS64649` / `65094` (private-use range) |
| `defang(value)` | `hxxps://evil[.]example[.]com/payload` |
| `cve_id(year=None)` / `notable_cve_id()` | `CVE-2022-31949` / `CVE-2021-44228` |
| `cwe_id()` / `cpe23(vendor, product, version, part="a")` | `CWE-502` / `cpe:2.3:a:apache:tomcat:8.4.1:*:*:*:*:*:*:*` |
| `mitre_attack_technique()` / `mitre_attack_technique_id(subtechnique=None)` | dict / `T1059.001` |
| `mitre_attack_tactic()` / `mitre_attack_tactic_id()` / `kill_chain_phase_name()` | dict / `TA0003` / `lateral-movement` |
| `malware_family()` / `threat_tool()` | `AgentTesla` / `PsExec` |
| `intrusion_set()` / `intrusion_set_profile()` / `mitre_attack_group_id()` | `APT29` / dict with aliases / `G0016` |
| `mutex_name()` / `windows_registry_key()` / `x509_serial_number()` | `Global\{025B…}` / `HKEY_…\Run` / `a5:b6:…` |

### STIX 2.1

| Formatter | Notes |
|---|---|
| `stix_id(stix_type=None, **properties)` | random UUIDv4, or the deterministic UUIDv5 when properties are given |
| `stix_type(category=None)` | `"sdo"`, `"sco"` or any |
| `stix_timestamp()` | `2020-11-15T11:52:11.445Z` |
| `tlp_level()` / `tlp_marking_id(level=None)` / `stix_marking_definition(level=None)` | well-known TLP ids (`clear`, `green`, `amber`, `amber+strict`, `red`) |
| `pap_level()` / `pap_marking_id(level=None)` | OpenCTI PAP marking ids |
| `stix_relationship_type()`, `stix_report_type()`, `stix_indicator_type()`, `stix_malware_type()`, `stix_identity_class()`, `stix_threat_actor_type()`, `stix_pattern_type()`, `industry_sector()` | STIX open vocabularies |
| `stix_kill_chain_phase()` / `stix_external_reference(source_name=None)` | |
| `stix_observable_value(stix_type)` / `stix_observable(stix_type=None, value=None, **extra)` | `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `mac-addr`, `hostname`, `file`, `autonomous-system`, `mutex` |
| `stix_pattern(stix_type=None, value=None)` | `[ipv4-addr:value = '…']`, `[file:hashes.'SHA-256' = '…']` |
| `stix_indicator(...)`, `stix_relationship(source_ref, target_ref, relationship_type)` | |
| `stix_attack_pattern(technique_id)`, `stix_malware(name)`, `stix_tool(name)`, `stix_intrusion_set(name)`, `stix_threat_actor(name)`, `stix_vulnerability(name)`, `stix_identity(name, identity_class)`, `stix_location(country_code)`, `stix_report(object_refs, name)` | SDOs with pycti-compatible ids |
| `stix_bundle(objects=None)` | |

Every object formatter accepts `**extra` keyword arguments, which are merged into the
result (`confidence=80`, `created_by_ref=…`, `x_opencti_score=…`).

### OpenCTI

| Formatter | Notes |
|---|---|
| `opencti_enrichment_message(entity_type=None, value=None, marking=None, score=None)` | what `process_message` receives; `entity_id`, `stix_entity` and `enrichment_entity` are consistent |
| `opencti_enrichment_entity(...)` / `opencti_stix_entity(...)` | the two halves of the message |
| `opencti_connector_config(connector_type=None, name=None)` / `opencti_connector_env(...)` | nested settings / `OPENCTI_URL`, `CONNECTOR_ID`… |
| `opencti_connector_type()`, `opencti_connector_scope()`, `opencti_duration_period()`, `opencti_work_id()` | |
| `opencti_marking(level=None)`, `opencti_author(name=None)`, `opencti_label()`, `opencti_score()`, `opencti_confidence()`, `opencti_internal_id()`, `opencti_observable_type()`, `opencti_entity_type()`, `opencti_timestamp()` | |

### OpenAEV

| Formatter | Notes |
|---|---|
| `openaev_implant_name(inject_id=None, agent_id=None, extension=None)` | `oaev-implant-<inject>-agent-<agent>`, the format collectors parse |
| `openaev_implant_command_line(inject_id=None, agent_id=None)` | as seen in EDR process evidence |
| `openaev_expectation(expectation_type=None, signature_types=None, inject_id=None, agent_id=None)` | implant `parent_process_name` + `start_date` < `end_date` by default |
| `openaev_expectation_signature(signature_type=None, value=None)` / `openaev_signature_value(signature_type)` | every pyoaev `SignatureTypes` value |
| `openaev_expectation_result(expectation_type=None, is_success=None, collector_id=None)` | `Detected` / `Not Detected` / `Prevented` / `Not Prevented` |
| `openaev_expectation_trace(...)`, `openaev_execution_callback(...)` | |
| `openaev_endpoint(platform=None, with_agent=True)`, `openaev_injection_message(...)` | |
| `openaev_collector_env(slug=None)`, `openaev_injector_env(slug=None)`, `openaev_collector_id(slug=None)` | |
| `openaev_ai_marker(inject_id=None, agent_id="")` | same algorithm as `pyoaev.signatures.ai_marker` |
| `openaev_id()`, `openaev_signature_type()`, `openaev_expectation_type()`, `openaev_execution_status()`, `openaev_execution_action()`, `openaev_security_platform_type()`, `openaev_cloud_provider()`, `openaev_platform()` | pyoaev enums |

## Use with factory_boy

Register the provider once (for example in `conftest.py`), then use `factory.Faker`:

```python
import factory
from faker_cti import CtiProvider

factory.Faker.add_provider(CtiProvider)


class StixIpv4EntityFactory(factory.DictFactory):
    value = factory.Faker("ipv4")
    # the id follows the value, even when the test overrides it
    id = factory.Faker("stix_id", stix_type="ipv4-addr", value=factory.SelfAttribute("..value"))
    x_opencti_score = factory.Faker("opencti_score")
    object_marking_refs = factory.List([factory.Faker("tlp_marking_id", level="amber")])


class EnrichmentMessageFactory(factory.DictFactory):
    class Params:
        entity_type = "IPv4-Addr"
        value = None

    message = factory.Faker(
        "opencti_enrichment_message",
        entity_type=factory.SelfAttribute("..entity_type"),
        value=factory.SelfAttribute("..value"),
    )

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        return kwargs["message"]


StixIpv4EntityFactory(value="1.2.3.4")["id"]  # 'ipv4-addr--0198f97b-…'
EnrichmentMessageFactory(entity_type="Domain-Name")
```

The [`examples/`](examples) folder has complete, tested examples based on the factories
of real connectors and collectors:

- [`opencti_enrichment`](examples/opencti_enrichment): an internal enrichment connector
  (replaces the ~500-line Censys / ReversingLabs factory files).
- [`openaev_collector`](examples/openaev_collector): an EDR collector matching alerts
  against expectations (Cortex XDR / XSOAR style).
- [`stix_bundle`](examples/stix_bundle): an external import connector producing a
  coherent bundle (author, marking, intrusion set, malware, attack pattern, relationships).

## Demo

```bash
uv run python examples/demo.py               # one sample of every formatter
uv run python examples/demo.py stix --seed 1 # filter + reproducible
faker -i faker_cti -r 3 stix_pattern         # with Faker's own CLI
```

## Development

```bash
uv sync
uv run pytest                     # tests + examples, with stix2 cross-checks
uv run --with pycti pytest -k pycti   # also cross-check ids against pycti
uv run ruff check . && uv run ruff format --check .
```

## License

Apache-2.0
