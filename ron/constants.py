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
class VPCConfig:
    MAX_AVAILABILITY_ZONE = 2
    SUBNET_NAME = "Public"
    AVAILABILITY_ZONES = ["us-east-1a", "us-east-1b", "us-east-1c"]


@dataclasses.dataclass
class RDSDatabase:
    CLOUDWATCH_LOG_EXPORTS = ["audit", "error", "general", "slowquery"]
    ALLOCATED_STORAGE = 20
    MAX_ALLOCATED_STORAGE = 1000


@dataclasses.dataclass
class LoadBalancer:
    PRODUCTION_WHITELISTED_IPS = {"3.139.112.56/32": "Prod Server"}


@dataclasses.dataclass
class AutoScaler:
    MIN = 2
    MAX = 5
    PERCENT = 75


@dataclasses.dataclass
class Fargate:
    CPU = 2048
    MEMORY_LIMIT = 4096
    CONTAINER_PORT = 3500
