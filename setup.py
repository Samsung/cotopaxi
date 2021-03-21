# -*- coding: utf-8 -*-
"""
Setup file for Cotopaxi.
"""
#
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz (Samsung R&D Poland)
#
#    This file is part of Cotopaxi.
#
#    Cotopaxi is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    Cotopaxi is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Cotopaxi.  If not, see <http://www.gnu.org/licenses/>.
#

try:
    from setuptools import setup, find_packages
except:
    raise ImportError("setuptools is required to install Cotopaxi!")
import os

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()


def package_files(directory):
    """Gathers paths to all files in a given directory."""
    paths = []
    for (path, _, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join("..", path, filename))
    return paths


PACKAGE_FILES = (
    package_files("cotopaxi/vulnerabilities/")
    + package_files("cotopaxi/fingerprinting")
    + package_files("cotopaxi/fuzzing_corpus")
    + package_files("cotopaxi/lists")
) + ["tests/test_config.ini", "tests/test_servers.yaml"]

setup(
    name="cotopaxi",
    version="1.3.0",
    author="Jakub Botwicz",
    author_email="j.botwicz@...",
    description="Set of tools for security testing of Internet of Things"
    " devices using specific network protocols.",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/Samsung/cotopaxi",
    packages=find_packages(),
    package_data={"cotopaxi": PACKAGE_FILES},
    include_package_data=True,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=2.7",
)
