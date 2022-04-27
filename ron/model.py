from typing import Mapping, List, Optional, Union

from pydantic import BaseModel


class ResourceParameters(BaseModel):
    name: Optional[str] = None


class IamParameters(ResourceParameters):
    assumed_by: str
    managed_policies: List[Mapping[str, str]]


class LoadBalancerParameters(ResourceParameters):
    ecr_repo_name: str
    desired_count: Optional[int] = 1
    health_check: str = "/"


class RDSDatabaseParameters(ResourceParameters):
    database_name: str
    database_port: Optional[int] = 3306


class VPCParameters(ResourceParameters):
    vpc_cidr: str
    vpc_cidr: Optional[str]


class ResourceModel(BaseModel):
    type: str
    parameters: Optional[
        Union[
            IamParameters, VPCParameters, RDSDatabaseParameters, LoadBalancerParameters
        ]
    ]


class LoadBalancer(ResourceModel):
    ...


class RDS(ResourceModel):
    ...


class Iam(ResourceModel):
    ...


class ECS(ResourceModel):
    ...


class VPC(ResourceModel):
    ...


class SecurityGroup(ResourceModel):
    ...


class StackModel(BaseModel):
    version: str
    metadata: Mapping[str, str]
    resources: List[Union[Iam, VPC, RDS, LoadBalancer, SecurityGroup]]
