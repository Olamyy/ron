import enum
from typing import Mapping, Optional, List, Any

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
from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk.aws_rds import CfnDBSubnetGroup
from aws_cdk.core import Environment, Duration, Aws, CfnOutput
import aws_cdk.aws_secretsmanager as secretsmanager

from ron.constants import VPCConfig, RDSDatabase, LoadBalancer, Fargate, AutoScaler
from ron.helpers import to_alpha_numeric, generate_random_cdk_like_suffix


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
            config: Mapping[str, Any],
            ecr_repo_name: str,
            **kwargs,
    ) -> None:
        self.config = config
        self.deployment_environment = deployment_environment
        env = self.get_environment()
        super().__init__(scope, env=env, **kwargs)

        self.resources = self.extract_resources()
        self.ecr_repo_name = ecr_repo_name
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
            resource_type = resource.get("type")
            parameters = resource.get("parameters")
            if resource_type == AWSResources.IAM_ROLE.value:
                self.add_role(parameters)
            elif resource_type == AWSResources.VPC.value:
                self.add_vpc(parameters)
            elif resource_type == AWSResources.ECS_CLUSTER.value:
                self.add_ecs_cluster()
            elif resource_type == AWSResources.EC2_SECURITY_GROUP.value:
                self.add_ec2_security_group()
            elif resource_type == AWSResources.RDS_DATABASE.value:
                self.add_database(parameters)
            elif resource_type == AWSResources.LOAD_BALANCER.value:
                self.add_load_balancer(parameters)

    @property
    def availability_zones(self) -> List[str]:
        return VPCConfig.AVAILABILITY_ZONES

    @staticmethod
    def get_environment():
        return Environment(account=Aws.ACCOUNT_ID, region=Aws.REGION)

    def add_role(self, iam_parameters: Mapping[str, Any]):
        """
        Add an IAM role to the stack
        """
        if not self.role:
            managed_policies = []
            for policies in iam_parameters.get("managed_policies"):
                for policy_name, policy_arn in policies.items():
                    policy_name = f"{policy_name}-policy"
                    managed_policy = iam.ManagedPolicy.from_managed_policy_arn(
                        self, id=policy_name, managed_policy_arn=policy_arn
                    )
                    managed_policies.append(managed_policy)

            role_name = f"{self.stack_name}-role"

            self.role = iam.Role(
                self,
                id=role_name,
                assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
                managed_policies=managed_policies,
            )

        return self.role

    def add_vpc(self, parameters: Mapping[str, Any]):
        """
        Add an EC2 VPC to the stack
        """

        if not self.vpc:
            vpc_name = f"{self.stack_name}-vpc"
            self.vpc = ec2.Vpc(
                self,
                id=vpc_name,
                max_azs=VPCConfig.MAX_AVAILABILITY_ZONE,
                cidr=parameters.get("vpc_cidr"),
                nat_gateways=1
            )

        return self.vpc

    def get_vpc(self, name: Optional[str] = None, cidr: Optional[str] = None):
        if not name or cidr:
            return self.vpc

        vpc = self.add_vpc({"vpc_cidr": cidr})
        return vpc

    def add_ecs_cluster(self):
        """
        Add ECS Cluster
        """
        if not self.ecs_cluster:
            vpc = self.get_vpc()

            cluster_name = f"{self.stack_name}-ecs-cluster"

            self.ecs_cluster = ecs.Cluster(
                self,
                id=cluster_name,
                vpc=vpc,
                container_insights=True
            )

        return self.ecs_cluster

    def add_ec2_security_group(self):
        """
        Add EC2 Security Group
        """
        if not self.security_group:
            vpc = self.get_vpc()
            security_group_name = f"{self.stack_name}-sg"
            self.security_group = ec2.SecurityGroup(
                self,
                id=security_group_name,
                vpc=vpc,
                allow_all_outbound=True
            )

            if self.allow_public_access():
                self.security_group.add_ingress_rule(
                    self.security_group,
                    connection=ec2.Port.all_tcp(),
                    remote_rule=True
                )
                self.security_group.add_egress_rule(
                    peer=ec2.Peer.any_ipv4(),
                    connection=ec2.Port.all_tcp()
                )
            # else:
            #     for ip_address, description in self.get_ips().items():
            #         self.security_group.add_ingress_rule(
            #             ec2.Peer.ipv4(ip_address),
            #             connection=ec2.Port.all_tcp(),
            #             description=description,
            #         )
            #         self.security_group.add_egress_rule(
            #             peer=ec2.Peer.ipv4(ip_address),
            #             connection=ec2.Port.all_tcp(),
            #             description=description,
            #         )

        return self.security_group

    def add_database(self, parameters: Mapping[str, Any]):
        """
        Add a DB Instance to the stack
        """
        vpc = ec2.Vpc(
            self,
            id=f"{self.stack_name}-rds-vpc",
            cidr="10.0.0.0/16",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    cidr_mask=24,
                    reserved=False,
                    subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(
                    name="private",
                    cidr_mask=24,
                    reserved=False,
                    subnet_type=ec2.SubnetType.PRIVATE),
                ec2.SubnetConfiguration(
                    name="DB",
                    cidr_mask=24,
                    reserved=False,
                    subnet_type=ec2.SubnetType.ISOLATED
                ),
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True
        )

        database_resource_id = f"{self.stack_name}-db-instance"
        database_instance_identifier = f"{self.stack_name}-{generate_random_cdk_like_suffix()}-db-identifier"

        database_instance = rds.DatabaseInstance(
            self,
            id=database_resource_id,
            instance_identifier=database_instance_identifier,
            database_name=to_alpha_numeric(parameters.get('database_name', f'{self.stack_name}-database')),
            engine=rds.DatabaseInstanceEngine.mysql(
                version=rds.MysqlEngineVersion.VER_8_0_23
            ),
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE
            ),
            port=parameters.get("database_port"),
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
            ),
            vpc=vpc,
            storage_type=rds.StorageType.GP2,
            storage_encrypted=True,
            backup_retention=cdk_core.Duration.days(0),
            cloudwatch_logs_exports=RDSDatabase.CLOUDWATCH_LOG_EXPORTS,
            allocated_storage=RDSDatabase.ALLOCATED_STORAGE,
            max_allocated_storage=RDSDatabase.MAX_ALLOCATED_STORAGE,
            publicly_accessible=True,
            removal_policy=cdk_core.RemovalPolicy.DESTROY,
        )

        cloudwatch.Alarm(
            self,
            id="HighCPU",
            metric=database_instance.metric_cpu_utilization(),
            threshold=90,
            evaluation_periods=1
        )

        database_instance.connections.allow_from_any_ipv4(ec2.Port.all_tcp())

        secretsmanager.Secret.from_secret_complete_arn(
            self,
            f"{self.stack_name}-database-secret",
            database_instance.secret.secret_arn,
        )

        return database_instance

    def restrict_to_whitelisted_ips(self, aws_resource):
        for ip_address, description in self.get_ips().items():
            aws_resource.add_ingress_rule(
                ec2.Peer.ipv4(ip_address),
                connection=ec2.Port.all_tcp(),
                description=description,
            )

    def add_load_balancer(self, parameters: Mapping[str, Any]):
        desired_count = parameters.get("desired_count")

        repo_name = f"{self.stack_name}-ecr-container"
        memory_limit = parameters.get("memory_limit")
        cpu = parameters.get("cpu")
        image = self.add_ecr_image(repo_name=self.ecr_repo_name or f"{self.stack_name}-ecr-repo")

        fargate_task_definition = self.add_fargate_task(
            repo_name=repo_name, image=image, memory_limit=memory_limit, cpu=cpu
        )

        load_balancer = self.get_load_balancer()

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

        CfnOutput(self,
                  "LoadBalancerHost",
                  value=load_balancing_service.load_balancer.load_balancer_dns_name)

    def get_ips(self):
        user_ips = self.config.get("metadata").get('whitelisted_ips')
        ips = LoadBalancer.PRODUCTION_WHITELISTED_IPS
        if user_ips:
            for ip_address, description in ips.items():
                if ip_address not in ips:
                    ips[ip_address] = description

        return ips

    def get_load_balancer(self):
        load_balancer_name = f"{self.stack_name}-load-balancer"
        load_balancer = elb.ApplicationLoadBalancer(
            self, id=load_balancer_name, vpc=self.vpc, internet_facing=True
        )

        load_balancer_security_group = self.add_ec2_security_group()

        if not self.allow_public_access():
            self.restrict_to_whitelisted_ips(load_balancer_security_group)

        load_balancer.add_security_group(load_balancer_security_group)
        return load_balancer

    def add_ecr_image(self, repo_name: str):
        ecr_repo_id = f"{repo_name}-ecr-repo"
        repo = ecr.Repository.from_repository_name(
            self, id=ecr_repo_id, repository_name=repo_name
        )

        return ecs.ContainerImage.from_ecr_repository(repo)

    def add_logger(self, name: str):
        return ecs.LogDriver.aws_logs(
            stream_prefix="logger-prefix",
            log_group=logs.LogGroup(self, f"{name}-logger"),
        )

    def add_fargate_task(
            self, repo_name, image, memory_limit=Fargate.MEMORY_LIMIT, cpu=Fargate.CPU
    ):
        fargate_task_id = f"{repo_name}-fargate-task"

        task = ecs.FargateTaskDefinition(
            self,
            id=fargate_task_id,
            cpu=cpu,
            memory_limit_mib=memory_limit,
            task_role=self.role,
        )
        container = task.add_container(
            f"{repo_name}-fargate-task-container",
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
            id=f"{self.stack_name}-{repo_name}-lb-service",
            cluster=self.ecs_cluster,
            task_definition=fargate_task,
            desired_count=desired_count,
            assign_public_ip=True,
            security_groups=[self.security_group],
            open_listener=self.allow_public_access(),
            load_balancer=load_balancer,
            listener_port=3500,
        )

    def allow_public_access(self):
        return self.deployment_environment not in ["staging", "production"]
