import enum
import json
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
from aws_cdk.aws_rds import Credentials
from aws_cdk.core import Environment, Duration, Aws
import aws_cdk.aws_secretsmanager as secretsmanager

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
            deployment_environment: str,
            scope: cdk_core.Construct,
            config: Mapping[str, Union[str, Dict]],
            **kwargs,
    ) -> None:
        self.config = config
        self.deployment_environment = deployment_environment
        stack_name = f"{self.config.get('metadata').get('stack_name')}-{self.deployment_environment}"
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
                cidr = resource.get("parameters").get("vpc_cidr")
                self.add_vpc(cidr)
            elif resource.get("type") == AWSResources.ECS_CLUSTER.value:
                self.add_ecs_cluster()
            elif resource.get("type") == AWSResources.EC2_SECURITY_GROUP.value:
                self.add_ec2_security_group()
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
            account=Aws.ACCOUNT_ID,
            region=Aws.REGION
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

            role_name = (
                f"{self.stack_name}-{generate_random_cdk_like_suffix()}-role"
            )

            self.role = iam.Role(
                self,
                id=role_name,
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
                managed_policies=managed_policies,
            )

        return self.role

    def add_vpc(self, cidr: str):
        """
        Add an EC2 VPC to the stack
        """

        if not self.vpc:
            vpc_name = f"{self.stack_name}-{generate_random_cdk_like_suffix()}-vpc"
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

    def add_ecs_cluster(self):
        """
        Add ECS Cluster
        """
        if not self.ecs_cluster:
            vpc = self.get_vpc()

            cluster_name = f"{self.stack_name}-{generate_random_cdk_like_suffix()}-ecs-cluster"

            self.ecs_cluster = ecs.Cluster(self, id=cluster_name, vpc=vpc)

        return self.ecs_cluster

    def add_ec2_security_group(self):
        """
        Add EC2 Security Group
        """

        if not self.security_group:
            vpc = self.get_vpc()
            security_group_name = (
                f"{self.stack_name}"
                f"-{generate_random_cdk_like_suffix()}-security-group"
            )
            self.security_group = ec2.SecurityGroup(
                self, id=security_group_name, vpc=vpc, allow_all_outbound=self.deployment_environment == "staging"
            )

            self.security_group.add_egress_rule(
                peer=ec2.Peer.any_ipv4(),
                connection=ec2.Port.all_tcp()
            )

        return self.security_group

    def add_database(self, resource: Mapping[str, Union[str, Dict]]):
        """
        Add a DB Instance to the stack
        """
        parameters = resource.get("parameters")

        database_security_group = self.add_ec2_security_group()

        database_security_group.add_ingress_rule(
            self.security_group, connection=ec2.Port.all_tcp(), remote_rule=True
        )

        database_resource_id = (
            f"{self.stack_name}-{parameters.get('database_name')}"
            f"-{generate_random_cdk_like_suffix()}-db-instance"
        )
        database_name = f"{parameters.get('database_name')}"
        database_instance_identifier = (
            f"{self.stack_name}"
            f"-{generate_random_cdk_like_suffix()}-db-identifier"
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
                ec2.InstanceClass.BURSTABLE3,
                ec2.InstanceSize.MICRO
            ),
            storage_type=rds.StorageType.GP2,
            storage_encrypted=True,
            backup_retention=cdk_core.Duration.days(0),
            cloudwatch_logs_exports=RDSDatabase.CLOUDWATCH_LOG_EXPORTS,
            allocated_storage=RDSDatabase.ALLOCATED_STORAGE,
            max_allocated_storage=RDSDatabase.MAX_ALLOCATED_STORAGE,
            publicly_accessible=self.deployment_environment == "staging",
            security_groups=[database_security_group],
            vpc_subnets=self.vpc.public_subnets[0],
            removal_policy=cdk_core.RemovalPolicy.DESTROY,
        )

        database_instance.connections.allow_from_any_ipv4(
            port_range=ec2.Port.all_tcp()
        )

        secretsmanager.Secret.from_secret_complete_arn(self,
                                                       f"{self.stack_name}-database-secret",
                                                       database_instance.secret.secret_arn)

        return database_instance

    def get_vpc(self, name: Optional[str] = None, cidr: Optional[str] = None):
        if not name or cidr:
            return self.vpc

        vpc = self.add_vpc(
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

        ips = self.get_ips(parameters.get("whitelisted_ips"))
        load_balancer = self.add_load_balancer()

        load_balancing_service = self.add_load_balancing_service(
            load_balancer=load_balancer,
            repo_name=repo_name,
            fargate_task=fargate_task_definition,
            desired_count=desired_count,
        )

        load_balancing_service.target_group.configure_health_check(
            path=parameters.get("health_check"),
            interval=Duration.seconds(120),
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
        ips = LoadBalancer.PRODUCTION_WHITELISTED_IPS
        if user_ips:
            for ip in user_ips:
                for ip_address, description in ip.items():
                    if ip_address not in ips:
                        ips[ip_address] = description

        return ips

    def add_load_balancer(self):
        load_balancer_name = f"{self.stack_name}-{generate_random_cdk_like_suffix()}-load-balancer"
        load_balancer = elb.ApplicationLoadBalancer(
            self, id=load_balancer_name, vpc=self.vpc, internet_facing=True
        )

        load_balancer_security_group = self.add_ec2_security_group()

        # for ip_address, description in ips.items():
        #     load_balancer_security_group.add_ingress_rule(
        #         ec2.Peer.ipv4(ip_address),
        #         connection=ec2.Port.all_tcp(),
        #         description=description,
        #     )

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
                container_port=Fargate.CONTAINER_PORT,
                protocol=ecs.Protocol.TCP
            )
        )

        return task

    def add_load_balancing_service(
            self, load_balancer, repo_name, fargate_task, desired_count
    ):
        print(self.deployment_environment)
        print(self.deployment_environment == "staging")
        return ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            id=f"{self.stack_name}-{repo_name}-{generate_random_cdk_like_suffix()}-lb-service",
            cluster=self.ecs_cluster,
            task_definition=fargate_task,
            desired_count=desired_count,
            assign_public_ip=True,
            security_groups=[self.security_group],
            open_listener=self.deployment_environment == "staging",
            load_balancer=load_balancer,
            listener_port=3500

        )
