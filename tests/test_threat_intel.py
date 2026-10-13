import re

import pytest

from faker_cti.data import mitre


def test_file_hashes_reuse_faker_hash_formatters(fake):
    """MD5/SHA-1/SHA-256 come from Faker's own ``md5``/``sha1``/``sha256``."""
    from faker import Faker

    from faker_cti import ThreatIntelProvider

    fakes = []
    for _ in range(2):
        f = Faker()
        f.add_provider(ThreatIntelProvider)
        f.seed_instance(7)
        fakes.append(f)
    assert fakes[0].file_hashes(["MD5"])["MD5"] == fakes[1].md5()


def test_asn_is_private(fake):
    for _ in range(100):
        assert 64512 <= fake.autonomous_system_number() <= 65534
        assert re.fullmatch(r"AS6[45]\d{3}", fake.asn())


def test_defang():
    from faker import Faker

    from faker_cti import ThreatIntelProvider

    fake = Faker()
    fake.add_provider(ThreatIntelProvider)
    assert fake.defang("https://evil.test/a") == "hxxps://evil[.]test/a"
    assert fake.defang("http://192.0.2.1") == "hxxp://192[.]0[.]2[.]1"
    assert fake.defang("a@b.test") == "a[@]b[.]test"


def test_file_hashes_default(fake):
    hashes = fake.file_hashes()
    assert set(hashes) == {"MD5", "SHA-1", "SHA-256"}
    assert re.fullmatch(r"[0-9a-f]{32}", hashes["MD5"])
    assert re.fullmatch(r"[0-9a-f]{40}", hashes["SHA-1"])
    assert re.fullmatch(r"[0-9a-f]{64}", hashes["SHA-256"])


def test_file_hashes_all_algorithms(fake):
    hashes = fake.file_hashes(["SHA-512", "SSDEEP", "TLSH"])
    assert re.fullmatch(r"[0-9a-f]{128}", hashes["SHA-512"])
    assert re.fullmatch(r"\d+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+", hashes["SSDEEP"])
    assert re.fullmatch(r"T1[0-9A-F]{70}", hashes["TLSH"])


def test_file_hashes_rejects_unknown_algorithm(fake):
    with pytest.raises(ValueError, match="CRC32"):
        fake.file_hashes(["CRC32"])


def test_cve_and_cwe(fake):
    assert re.fullmatch(r"CVE-2021-\d{4,5}", fake.cve_id(year=2021))
    for _ in range(50):
        assert re.fullmatch(r"CVE-20(1[5-9]|2[0-5])-\d{4,5}", fake.cve_id())
        assert re.fullmatch(r"CVE-\d{4}-\d{4,5}", fake.notable_cve_id())
        assert re.fullmatch(r"CWE-\d+", fake.cwe_id())


def test_cpe23(fake):
    assert fake.cpe23("acme", "widget", "1.2.3") == "cpe:2.3:a:acme:widget:1.2.3:*:*:*:*:*:*:*"
    assert re.fullmatch(r"cpe:2\.3:o:[a-z_-]+:[a-z_-]+:\d\.\d\.\d(:\*){7}", fake.cpe23(part="o"))


def test_mitre_technique(fake):
    technique = fake.mitre_attack_technique()
    assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique["external_id"])
    assert technique["url"].startswith("https://attack.mitre.org/techniques/T")
    assert technique["phase_name"] in {t[2] for t in mitre.TACTICS}


def test_mitre_technique_id_filters(fake):
    for _ in range(50):
        assert "." in fake.mitre_attack_technique_id(subtechnique=True)
        assert "." not in fake.mitre_attack_technique_id(subtechnique=False)


def test_mitre_tactic(fake):
    tactic = fake.mitre_attack_tactic()
    assert re.fullmatch(r"TA\d{4}", tactic["external_id"])
    assert tactic["url"].endswith(tactic["external_id"])
    assert re.fullmatch(r"TA\d{4}", fake.mitre_attack_tactic_id())


def test_mitre_data_is_consistent():
    phases = {t[2] for t in mitre.TACTICS}
    ids = [t[0] for t in mitre.TECHNIQUES]
    assert len(ids) == len(set(ids))
    assert all(t[2] in phases for t in mitre.TECHNIQUES)


def test_intrusion_set_profile(fake):
    profile = fake.intrusion_set_profile()
    assert re.fullmatch(r"G\d{4}", profile["external_id"])
    assert profile["aliases"]
    assert re.fullmatch(r"G\d{4}", fake.mitre_attack_group_id())


def test_x509_serial_number(fake):
    assert re.fullmatch(r"([0-9a-f]{2}:){15}[0-9a-f]{2}", fake.x509_serial_number())
