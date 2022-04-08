import enum
from typing import Mapping, Union, Dict, Optional, List

import click
from aws_cdk import core as cdk_core
from aws_cdk import aws_iam as iam
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_rds as rds
from aws_cdk import aws_logs as logs
from aws_cdk import aws_ecs_patterns as ecs_patterns
from aws_cdk import aws_elasticloadbalancingv2 as elb
from aws_cdk import aws_ecr as ecr
from aws_cdk.core import Environment

from ron.constants import VPC, RDSDatabase, LoadBalancer, Fargate, AutoScaler
from ron.helpers import generate_random_cdk_like_suffix


class AWSResources(enum.Enum):
    ECS_CLUSTER = "ECS_CLUSTER"
    IAM_ROLE = "IAM_ROLE"
    EC2_SECURITY_GROUP = "EC2_SECURITY_GROUP"
    RDS_DATABASE = "RDS_DATABASE"
    LOAD_BALANCER = "LOAD_BALANCER"
    VPC = "VPC"


class AWSStack(cdk_core.Stack):
    def __init__(
        self,
        scope: cdk_core.Construct,
        config: Mapping[str, Union[str, Dict]],
        **kwargs,
    ) -> None:
        self.config = config
        stack_name = self.config.get("metadata").get("stack_name")
        env = self.setup_environment(self.config.get("environment"))
        super().__init__(scope, stack_name=stack_name, env=env, **kwargs)

        self.resources = self.extract_resources()
        self.vpc = None
        self.security_group = None
        self.role = None
        self.ecs_cluster = None
        self.logger = None

    def extract_resources(self):
        if "resources" not in self.config:
            return click.secho("No resource found in config. Aborting", fg="red")
        else:
            resources = self.config["resources"]
        return resources

    def build(self):
        for resource in self.resources:
            if resource.get("type") == AWSResources.IAM_ROLE.value:
                self.add_role(resource)
            elif resource.get("type") == AWSResources.VPC.value:
                name = resource.get("parameters").get("vpc_name")
                cidr = resource.get("parameters").get("vpc_cidr")
                self.add_vpc(name, cidr)
            elif resource.get("type") == AWSResources.ECS_CLUSTER.value:
                self.add_ecs_cluster(resource)
            elif resource.get("type") == AWSResources.EC2_SECURITY_GROUP.value:
                self.add_ec2_security_group(resource)
            elif resource.get("type") == AWSResources.RDS_DATABASE.value:
                self.add_database(resource)
            elif resource.get("type") == AWSResources.LOAD_BALANCER.value:
                self.add_autoscaler(resource)

    @property
    def availability_zones(self) -> List[str]:
        return VPC.AVAILABILITY_ZONES

    @staticmethod
    def setup_environment(environment: Dict):
        return Environment(
            account=environment.get("account"), region=environment.get("region")
        )

    def add_role(self, resource: Mapping[str, Union[str, Dict]]):
        """
        Add an IAM role to the stack
        """
        if not self.role:
            managed_policies = []
            for policies in resource.get("parameters").get("managed_policies"):
                for policy_name, policy_arn in policies.items():
                    policy_name = (
                        f"{policy_name}-{generate_random_cdk_like_suffix()}-policy"
                    )
                    managed_policy = iam.ManagedPolicy.from_managed_policy_arn(
                        self, id=policy_name, managed_policy_arn=policy_arn
                    )
                    managed_policies.append(managed_policy)

            parameters = resource.get("parameters")
            role_name = (
                f"{parameters.get('name')}-{generate_random_cdk_like_suffix()}-role"
            )

            self.role = iam.Role(
                self,
                id=role_name,
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
                managed_policies=managed_policies,
            )

        return self.role

    def add_vpc(self, name: str, cidr: str):
        """
        Add an EC2 VPC to the stack
        """

        if not self.vpc:
            vpc_name = f"{name}-{generate_random_cdk_like_suffix()}-vpc"
            self.vpc = ec2.Vpc(
                self,
                id=vpc_name,
                max_azs=VPC.MAX_AVAILABILITY_ZONE,
                cidr=cidr,
                subnet_configuration=[
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PUBLIC, name=VPC.SUBNET_NAME
                    )
                ],
            )

        return self.vpc

    def add_ecs_cluster(self, resource: Mapping[str, Union[str, Dict]]):
        """
        Add ECS Cluster
        """
        if not self.ecs_cluster:
            vpc = self.get_vpc()

            cluster_name = f"{resource.get('parameters').get('name')}-{generate_random_cdk_like_suffix()}-ecs-cluster"

            self.ecs_cluster = ecs.Cluster(self, id=cluster_name, vpc=vpc)

        return self.ecs_cluster

    def add_ec2_security_group(self, resource: Mapping[str, Union[str, Dict]]):
        """
        Add EC2 Security Group
        """

        if not self.security_group:
            vpc = self.get_vpc()
            security_group_name = (
                f"{resource.get('parameters').get('name')}"
                f"-{generate_random_cdk_like_suffix()}-security-group"
            )
            self.security_group = ec2.SecurityGroup(
                self, id=security_group_name, vpc=vpc
            )

        return self.security_group

    def add_database(self, resource: Mapping[str, Union[str, Dict]]):
        """
        Add a DB Instance to the stack
        """
        parameters = resource.get("parameters")

        database_security_group = self.add_ec2_security_group(
            resource={
                "parameters": {
                    "name": f"{parameters.get('security_group_name')}"
                    f"-{generate_random_cdk_like_suffix()}-security-group"
                }
            }
        )

        database_security_group.add_ingress_rule(
            self.security_group, connection=ec2.Port.all_tcp(), remote_rule=True
        )

        database_resource_id = (
            f"{self.stack_name}-{parameters.get('database_name')}"
            f"-{generate_random_cdk_like_suffix()}-database-instance"
        )
        database_name = f"{parameters.get('database_name')}database"
        database_instance_identifier = (
            f"{parameters.get('database_name')}"
            f"-{generate_random_cdk_like_suffix()}-database-instance-identifier"
        )

        database_instance = rds.DatabaseInstance(
            self,
            id=database_resource_id,
            instance_identifier=database_instance_identifier,
            database_name=database_name,
            engine=rds.DatabaseInstanceEngine.mysql(
                version=rds.MysqlEngineVersion.VER_8_0_23
            ),
            vpc=self.vpc,
            port=int(resource.get("parameters").get("database_port")),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
            ),
            storage_type=rds.StorageType.GP2,
            storage_encrypted=True,
            backup_retention=cdk_core.Duration.days(0),
            cloudwatch_logs_exports=RDSDatabase.CLOUDWATCH_LOG_EXPORTS,
            allocated_storage=RDSDatabase.ALLOCATED_STORAGE,
            max_allocated_storage=RDSDatabase.MAX_ALLOCATED_STORAGE,
            publicly_accessible=False,
            security_groups=[database_security_group],
            vpc_subnets=self.vpc.public_subnets[0],
            removal_policy=cdk_core.RemovalPolicy.DESTROY,
        )
        return database_instance

    def get_vpc(self, name: Optional[str] = None, cidr: Optional[str] = None):
        if not name or cidr:
            return self.vpc

        vpc = self.add_vpc(
            name=name,
            cidr=cidr,
        )
        return vpc

    def add_autoscaler(self, resource: Mapping[str, Union[str, Dict]]):
        parameters = resource.get("parameters")

        desired_count = parameters.get("desired_count", 0)

        repo_name = parameters.get("ecr_repo_name")
        image = self.add_ecr_image(repo_name=repo_name)

        fargate_task_definition = self.add_fargate_task(
            repo_name=repo_name, image=image
        )

        if desired_count > 0:
            ips = self.get_ips(parameters.get("whitelisted_ips"))
            load_balancer = self.add_load_balancer(ips=ips, name=parameters.get("name"))

            load_balancing_service = self.add_load_balancing_service(
                load_balancer=load_balancer,
                repo_name=repo_name,
                fargate_task=fargate_task_definition,
                desired_count=desired_count,
            )

            scalable_target = load_balancing_service.service.auto_scale_task_count(
                min_capacity=AutoScaler.MIN, max_capacity=AutoScaler.MIN
            )
            scalable_target.scale_on_cpu_utilization(
                "CpuScaling", target_utilization_percent=AutoScaler.PERCENT
            )
            scalable_target.scale_on_memory_utilization(
                "MemoryScaling", target_utilization_percent=AutoScaler.PERCENT
            )

    @staticmethod
    def get_ips(user_ips: Optional[List[Dict]] = None):
        ips = LoadBalancer.WHITELISTED_IPS
        if user_ips:
            for ip in user_ips:
                for ip_address, description in ip.items():
                    if ip_address not in ips:
                        ips[ip_address] = description

        return ips

    def add_load_balancer(self, ips: Dict, name: str):
        load_balancer_name = f"{self.stack_name}-{generate_random_cdk_like_suffix()}-{name}-load-balancer"
        load_balancer = elb.ApplicationLoadBalancer(
            self, id=load_balancer_name, vpc=self.vpc, internet_facing=True
        )

        load_balancer_security_group = self.add_ec2_security_group(
            resource={
                "parameters": {
                    "name": f"{name}-{generate_random_cdk_like_suffix()}-security-group"
                }
            }
        )

        for ip_address, description in ips.items():
            load_balancer_security_group.add_ingress_rule(
                ec2.Peer.ipv4(ip_address),
                connection=ec2.Port.all_tcp(),
                description=description,
            )

        load_balancer.add_security_group(load_balancer_security_group)
        return load_balancer

    def add_ecr_image(self, repo_name: str):
        ecr_repo_id = f"{repo_name}-{generate_random_cdk_like_suffix()}-ecr-repo"
        repo = ecr.Repository.from_repository_name(
            self, id=ecr_repo_id, repository_name=repo_name
        )

        return ecs.ContainerImage.from_ecr_repository(repo)

    def add_logger(self, name: str):
        return ecs.LogDriver.aws_logs(
            stream_prefix="logger-prefix",
            log_group=logs.LogGroup(self, f"{name}-logger"),
        )

    def add_fargate_task(self, repo_name, image):
        fargate_task_id = (
            f"{repo_name}-{generate_random_cdk_like_suffix()}-fargate-task"
        )

        task = ecs.FargateTaskDefinition(
            self,
            id=fargate_task_id,
            cpu=Fargate.CPU,
            memory_limit_mib=Fargate.MEMORY_LIMIT,
            task_role=self.role,
        )
        container = task.add_container(
            f"{repo_name}-{generate_random_cdk_like_suffix()}-fargate-task-container",
            image=image,
            logging=self.add_logger(fargate_task_id),
        )

        container.add_port_mappings(
            ecs.PortMapping(
                container_port=Fargate.CONTAINER_PORT, protocol=ecs.Protocol.TCP
            )
        )

        return task

    def add_load_balancing_service(
        self, load_balancer, repo_name, fargate_task, desired_count
    ):
        return ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            id=f"{self.stack_name}-{repo_name}-{generate_random_cdk_like_suffix()}-lb-service",
            cluster=self.ecs_cluster,
            task_definition=fargate_task,
            desired_count=desired_count,
            assign_public_ip=True,
            security_groups=[self.security_group],
            open_listener=False,
            load_balancer=load_balancer,
        )
