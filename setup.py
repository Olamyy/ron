#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This file is used to create the package we'll publish to PyPI.

.. currentmodule:: setup.py
.. moduleauthor:: ola <ola.wahab@languageio.com>
"""

import importlib.util
import io
import os
from pathlib import Path
from setuptools import setup, find_packages
from codecs import open  # Use a consistent encoding.
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()

# Get the base version from the library.  (We'll find it in the `version.py`
# file in the src directory, but we'll bypass actually loading up the library.)
vspec = importlib.util.spec_from_file_location(
    "version", str(Path(__file__).resolve().parent / "ron" / "version.py")
)
vmod = importlib.util.module_from_spec(vspec)
vspec.loader.exec_module(vmod)
version = getattr(vmod, "__version__")

with io.open(os.path.join(here, "requirements.txt")) as f:
    lines = f.readlines()
    REQUIRED = [x.strip() for x in lines if not x.startswith("--")]

# If the environment has a build number set...
if os.getenv("buildnum") is not None:
    # ...append it to the version.
    version = f"{version}.{os.getenv('buildnum')}"

setup(
    name="ron",
    description="A wrapper around AWS CDK for generating resources",
    long_description=long_description,
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    version=version,
    install_requires=REQUIRED,
    entry_points="""
    [console_scripts]
    ron=ron.cli:cli
    """,
    python_requires=">=0.0.1",
    license=None,  # noqa
    author="ola",
    author_email="ola.wahab@languageio.com",
    # Use the URL to the github repo.
    url="https://github.com/ola/ron",
    include_package_data=True,
)
