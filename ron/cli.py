#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sys
import tempfile
from glob import glob

import click
from aws_cdk import core as cdk_core
from cfn_flip import to_yaml

from ron.constants import LOGGING_LEVELS
from ron.helpers import read_ron_config, write_to_file
from ron.stack import AWSStack


class Info(object):
    """An information object to pass data between CLI functions."""

    def __init__(self):  # Note: This object must have an empty constructor.
        """Create a new instance."""
        self.verbose: int = 0
        self.app = None


pass_info = click.make_pass_decorator(Info, ensure=True)


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enables verbose mode.")
@click.version_option()
@pass_info
def cli(info: Info, verbose: int):
    if verbose > 0:
        logging.basicConfig(
            level=LOGGING_LEVELS[verbose]
            if verbose in LOGGING_LEVELS
            else logging.DEBUG
        )
        click.echo(
            click.style(
                f"Verbose logging is enabled. "
                f"(LEVEL={logging.getLogger().getEffectiveLevel()})",
                fg="yellow",
            )
        )
    info.verbose = verbose


@cli.command()
@click.help_option()
@click.option("--config", help="Path to your YAML configuration")
@click.option("-ecr", "--ecr_repo_name", help="ECR Repository Name")
@click.option("-e", "--environment", help="Environment to deploy to", default="staging")
@pass_info
def generate(info: Info, environment: str, config: str = None, ecr_repo_name: str = None):
    """Generate Cloudformation YAML."""

    configs = read_ron_config(config)

    if not configs:
        click.secho(
            "Could not find config. Are you sure you're running ron from your project root? "
            "You can also pass --config_path to the command to manually pass a path",
            fg="red",
        )
        sys.exit()

    else:
        for config in configs:
            output_directory = tempfile.mkdtemp()
            app = cdk_core.App(outdir=output_directory, auto_synth=True)

            stack_name = f"{config.get('metadata')['stack_name']}"

            AWSStack(
                scope=app,
                stack_name=stack_name,
                deployment_environment=environment,
                ecr_repo_name=ecr_repo_name,
                config=config,
            ).build()

            app.synth(validate_on_synthesis=True)

            with open(glob(f"{output_directory}/*.template.json")[0]) as content:
                content = content.read()

                yaml_content = to_yaml(content)

            write_to_file(
                template=yaml_content, location=f"deploy/apply/{stack_name}.yaml"
            )
