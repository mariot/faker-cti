import pytest
from faker import Faker

from faker_cti import CtiProvider


@pytest.fixture
def fake() -> Faker:
    faker = Faker()
    faker.add_provider(CtiProvider)
    faker.seed_instance(4321)
    return faker
