from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from random import Random

from faker_cti.data.stix import STIX_NAMESPACE

_NAMESPACE = uuid.UUID(STIX_NAMESPACE)
_EPOCH_START = datetime(2020, 1, 1, tzinfo=timezone.utc)
_EPOCH_SPAN_SECONDS = int(
    (datetime(2026, 1, 1, tzinfo=timezone.utc) - _EPOCH_START).total_seconds()
)


def random_uuid4(rng: Random) -> str:
    """UUIDv4 drawn from the Faker random instance, so ``Faker.seed`` makes it reproducible."""
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def canonical_json(data: dict) -> str:
    """JSON canonicalization (RFC 8785) for flat dicts of strings, as used by STIX/pycti."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def deterministic_uuid(data: dict) -> str:
    """UUIDv5 in the STIX namespace, matching ``stix2`` and ``pycti`` ``generate_id`` helpers."""
    return str(uuid.uuid5(_NAMESPACE, canonical_json(data)))


def random_hex(rng: Random, length: int) -> str:
    return f"{rng.getrandbits(length * 4):0{length}x}"


def random_datetime(rng: Random) -> datetime:
    return _EPOCH_START + timedelta(seconds=rng.randint(0, _EPOCH_SPAN_SECONDS))


def stix_timestamp(value: datetime) -> str:
    """Format a datetime the way STIX 2.1 serializes it (UTC, millisecond precision, ``Z``)."""
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
