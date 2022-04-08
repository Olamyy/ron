import dataclasses
import logging

LOGGING_LEVELS = {
    0: logging.NOTSET,
    1: logging.ERROR,
    2: logging.WARN,
    3: logging.INFO,
    4: logging.DEBUG,
}


@dataclasses.dataclass
class VPC:
    MAX_AVAILABILITY_ZONE = 2
    SUBNET_NAME = "Public"
    AVAILABILITY_ZONES = ["us-east-2a", "us-east-2b", "us-east-2c"]


@dataclasses.dataclass
class RDSDatabase:
    CLOUDWATCH_LOG_EXPORTS = ["audit", "error", "general", "slowquery"]
    ALLOCATED_STORAGE = 20
    MAX_ALLOCATED_STORAGE = 1000


@dataclasses.dataclass
class LoadBalancer:
    WHITELISTED_IPS = {"3.139.112.56/32": "Prod Server"}


@dataclasses.dataclass
class AutoScaler:
    MIN = 2
    MAX = 5
    PERCENT = 75


@dataclasses.dataclass
class Fargate:
    CPU = 256
    MEMORY_LIMIT = 512
    CONTAINER_PORT = 3500
