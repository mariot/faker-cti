"""Print one sample of every faker-cti formatter.

uv run python examples/demo.py            # everything
uv run python examples/demo.py stix       # only formatters containing "stix"
uv run python examples/demo.py --seed 42  # reproducible output
"""

import argparse
import inspect
import json

from faker import Faker
from faker.providers import BaseProvider

from faker_cti import OpenAEVProvider, OpenCTIProvider, StixProvider, ThreatIntelProvider

REQUIRED_ARGS = {
    "defang": ("https://evil.example.com/payload",),
    "stix_observable_value": ("ipv4-addr",),
    "openaev_signature_value": ("parent_process_name",),
}


def own_formatters(provider: type[BaseProvider]) -> list[str]:
    inherited = set(dir(BaseProvider))
    for parent in provider.__mro__[1:]:
        if parent is not BaseProvider and issubclass(parent, BaseProvider):
            inherited |= set(vars(parent))
    return sorted(
        name
        for name, member in vars(provider).items()
        if inspect.isfunction(member) and not name.startswith("_") and name not in inherited
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("filter", nargs="?", default="")
    parser.add_argument("--seed", type=int)
    args = parser.parse_args()

    fake = Faker()
    for provider in (ThreatIntelProvider, StixProvider, OpenCTIProvider, OpenAEVProvider):
        fake.add_provider(provider)
    if args.seed is not None:
        fake.seed_instance(args.seed)

    for provider in (ThreatIntelProvider, StixProvider, OpenCTIProvider, OpenAEVProvider):
        names = [n for n in own_formatters(provider) if args.filter in n]
        if not names:
            continue
        print(f"\n\033[1m# {provider.__name__}\033[0m")
        for name in names:
            value = getattr(fake, name)(*REQUIRED_ARGS.get(name, ()))
            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2)
            print(f"\033[36m{name}\033[0m: {value}")


if __name__ == "__main__":
    main()
