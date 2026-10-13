# Changelog

## 0.1.0

Initial release:

- `ThreatIntelProvider`: hashes, ssdeep, TLSH, ASN, CVE/CWE/CPE, MITRE ATT&CK, threat names.
- `StixProvider`: STIX 2.1 ids (deterministic ids identical to `stix2`/`pycti`), markings,
  vocabularies, patterns, observables, domain objects, relationships and bundles.
- `OpenCTIProvider`: enrichment messages, connector configuration, OpenCTI entity shapes.
- `OpenAEVProvider`: implant names, expectations, signatures, results, endpoints, messages.
- `CtiProvider`: every formatter in one provider.
