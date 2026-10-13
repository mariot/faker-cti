"""Factories for an OpenCTI *external import* connector producing STIX bundles.

Shows how to compose faker-cti formatters into a coherent graph: an author, a TLP
marking, an intrusion set using a malware and an attack pattern, and a report
containing them all. The bundle is parsed by the reference ``stix2`` library.
"""

import factory
import stix2

from faker_cti import CtiProvider

factory.Faker.add_provider(CtiProvider)


class ThreatReportBundleFactory(factory.DictFactory):
    class Params:
        tlp = "amber"
        author = factory.Faker("opencti_author")
        intrusion_set = factory.Faker("stix_intrusion_set")
        malware = factory.Faker("stix_malware")
        attack_pattern = factory.Faker("stix_attack_pattern")
        marking = factory.Faker("tlp_marking_id", level=factory.SelfAttribute("..tlp"))
        uses_malware = factory.Faker(
            "stix_relationship",
            source_ref=factory.LazyAttribute(lambda o: o.factory_parent.intrusion_set["id"]),
            target_ref=factory.LazyAttribute(lambda o: o.factory_parent.malware["id"]),
            relationship_type="uses",
        )
        uses_technique = factory.Faker(
            "stix_relationship",
            source_ref=factory.LazyAttribute(lambda o: o.factory_parent.malware["id"]),
            target_ref=factory.LazyAttribute(lambda o: o.factory_parent.attack_pattern["id"]),
            relationship_type="uses",
        )

    type = "bundle"
    id = factory.Faker("stix_id", stix_type="bundle")
    objects = factory.LazyAttribute(
        lambda o: [
            o.author,
            *(
                {**obj, "created_by_ref": o.author["id"], "object_marking_refs": [o.marking]}
                for obj in (
                    o.intrusion_set,
                    o.malware,
                    o.attack_pattern,
                    o.uses_malware,
                    o.uses_technique,
                )
            ),
        ]
    )


def test_bundle_is_valid_stix():
    bundle = stix2.parse(ThreatReportBundleFactory(), allow_custom=True)
    types = [obj.type for obj in bundle.objects]
    assert types == [
        "identity",
        "intrusion-set",
        "malware",
        "attack-pattern",
        "relationship",
        "relationship",
    ]


def test_relationships_point_to_objects_in_the_bundle():
    bundle = ThreatReportBundleFactory()
    ids = {obj["id"] for obj in bundle["objects"]}
    for relationship in (o for o in bundle["objects"] if o["type"] == "relationship"):
        assert {relationship["source_ref"], relationship["target_ref"]} <= ids


def test_every_object_is_marked_and_attributed():
    bundle = ThreatReportBundleFactory(tlp="red")
    author, *objects = bundle["objects"]
    for obj in objects:
        assert obj["created_by_ref"] == author["id"]
        assert obj["object_marking_refs"] == [stix2.TLP_RED.id]
