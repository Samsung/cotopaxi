# -*- coding: utf-8 -*-
"""Setup file for Cotopaxi."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz
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

import os
import sys

try:
    import pip
    from setuptools import setup, find_packages
except ImportError:
    sys.exit("pip and setuptools are required to install Cotopaxi!")

if sys.version_info[0] > 2 and int(pip.__version__.split(".")[0]) < 20:
    sys.exit(
        "\npip >= 20 is required to install Cotopaxi! (current version: "
        + pip.__version__
        + ")\nUse the following command to upgrade: python -m pip install --upgrade pip\n"
    )

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
    package_files("cotopaxi/fingerprinting")
    + package_files("cotopaxi/fuzzing_corpus")
    + package_files("cotopaxi/identification_models")
    + package_files("cotopaxi/lists")
    + package_files("cotopaxi/vulnerabilities")
    + ["LICENSE"]
)

EXTRAS_DEV = [
    'bandit; python_version > "3.0.0"',
    'black; python_version > "3.0.0"',
    "configparser",
    "coverage",
    "pre-commit",
    "pydocstyle",
    "pylint",
    "pytest",
    "timeout-decorator",
]
EXTRAS_ML = [
    'pandas>=1.0.5; python_version > "3.0.0"',
    'sklearn; python_version > "3.0.0"',
    'tensorflow>=2.2.0; python_version > "3.0.0"',
    'xgboost; python_version > "3.0.0"',
]
EXTRAS_ALL = EXTRAS_DEV + EXTRAS_ML

setup(
    name="cotopaxi",
    version="1.7.0",
    author="Jakub Botwicz",
    author_email="cotopaxi.tool@protonmail.com",
    description="Set of tools for security testing of Internet of Things"
    " devices using specific network protocols.",
    keywords="IoT, security, network, protocols, fuzzing, fingerprinting, vulnerabilities,"
    " server, client, DDoS, traffic amplification, security configuration, supported ciphers,"
    " TCP, UDP, IPv4, IPv6, AMQP, CoAP, DTLS, HTCPCP, HTTP/2, gRPC, KNX, mDNS,"
    " MQTT, MQTT-SN, QUIC, RTSP, SSDP",
    license="GPLv2",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/Samsung/cotopaxi",
    packages=find_packages(include=["cotopaxi", "cotopaxi.*"]),
    package_data={"cotopaxi": PACKAGE_FILES},
    # entry_points={
    #     'console_scripts': ['cotopaxi.service_ping=cotopaxi.service_ping:main'],
    # },
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
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Topic :: Scientific/Engineering",
        "Topic :: Security",
        "Topic :: Software Development",
        "Topic :: Software Development :: Testing",
        "Topic :: System",
        "Topic :: System :: Networking",
    ],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, !=3.9.*, <4",
    project_urls={
        "Bug Reports": "https://github.com/Samsung/cotopaxi/issues",
        "Source Code": "https://github.com/Samsung/cotopaxi",
    },
    install_requires=[
        "dnslib>=0.9.7",
        'enum34; python_version < "3.0.0"',
        "grpcio",
        "IPy>=0.83",
        "pycryptodomex",
        "PyYAML>=3.12",
        "scapy>=2.4.3",
        'validators==0.16; python_version < "3.0.0"',
        'validators; python_version < "4.0.0"',
    ],
    extras_require={"all": EXTRAS_ALL, "dev": EXTRAS_DEV, "ml": EXTRAS_ML,},
    include_package_data=True,
    zip_safe=False,
)
