#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metasploit wrapper for cotopaxi.active_scanner."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
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

import importlib.util
import logging
from pathlib import Path
import traceback

try:
    from metasploit import module
    from cotopaxi.common_utils import Protocol
    from cotopaxi.cotopaxi_tester import PROTOCOL_TESTERS
    from cotopaxi.active_scanner import main

    spec = importlib.util.spec_from_file_location(
        "common_utils",
        Path(__file__).absolute().parents[2] / "cotopaxi" / "common_utils.py",
    )
    common_utils = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common_utils)

    DEPENDENCIES_MISSING = False
except ImportError:
    module.log("Error: {}".format(traceback.format_exc()), "error")
    DEPENDENCIES_MISSING = True

METADATA = {
    "name": "Verification of security properties of network endpoints at given IP and port ranges",
    "description": """
        ...
        (wrapper for cotopaxi.active_scanner)
    """,
    "authors": ["Jakub Botwicz"],
    "date": "2021-05-01",
    "license": "GPL_LICENSE",
    "references": [{"type": "url", "ref": "https://github.com/Samsung/cotopaxi"},],
    "type": "single_scanner",
    "options": {
        "RHOSTS": common_utils.PARAMETER_RHOSTS,
        "RPORTS": {
            "type": "string",
            "description": "Target ports",
            "required": True,
            "default": "top-100",
        },
    },
}


def prepare_metadata_active_scanner(protocol):
    """Generate metadata for metasploit ping modules."""
    return {
        "name": '"Ping" for ' + protocol + " protocol",
        "description": (
            " Checks availability of " + protocol + " server "
            "by sending dedicated set of "
            + protocol
            + " messages and waiting for response."
            "Requires installation of Cotopaxi framework for Python 3!"
        ),
        "authors": ["Jakub Botwicz"],
        "date": "2021-03-14",
        "license": "GPL_LICENSE",
        "references": [{"type": "url", "ref": "https://github.com/Samsung/cotopaxi"},],
        "type": "single_scanner",
        "options": {
            "RHOSTS": common_utils.PARAMETER_RHOSTS,
            "RPORTS": {
                "type": "string",
                "description": "Target ports described by number of port or multiple ports "
                'given by list separated by comas (e.g. "8080,9090") or port range '
                '(e.g. "1000-2000") or mix of both',
                "required": True,
                "default": PROTOCOL_TESTERS[
                    getattr(Protocol, protocol.upper())
                ].default_port(),
            },
        },
    }


# pylint: disable=broad-except
def run(args):
    """Execute wrapper using provided arguments."""
    module.LogHandler.setup(msg_prefix="{} - ".format(args["RHOSTS"]))
    if DEPENDENCIES_MISSING:
        logging.error("Module dependency (requests) is missing, cannot continue")
        return

    try:
        cotopaxi_output = common_utils.scrap_output(
            main, [args["RHOSTS"], args["RPORTS"], "-P", "DTLS"]
        )
        module.log(cotopaxi_output, "error")
        start_index = cotopaxi_output.find("Identified issues:")
        end_index = cotopaxi_output.find("Total number", start_index)
        if start_index < 0 or end_index < 0:
            raise Exception("Incorrect format of Cotopaxi response!")
        protocol_services = cotopaxi_output[
            start_index + 2 : end_index - 1
        ].splitlines()[1:]
        for protocol_service in protocol_services:
            name_start = protocol_service.find("Protocol.")
            name_end = protocol_service.find(":", name_start)
            proto_name = protocol_service[name_start + len("Protocol.") : name_end]
            services = protocol_service[name_end + 3 : -1].split(",")
            for service in services:
                service = service.strip(" '")
                service = service.split(":")
                service_ip = service[0]
                service_port = service[1].split(" ")[0]
                vuln_name = service[2]
                transport_proto = (
                    PROTOCOL_TESTERS[getattr(Protocol, proto_name)]
                    .transport_protocol()
                    .__name__
                )
                module.log(
                    "Found service - host: {} port: {} proto: {} over {}".format(
                        service_ip, service_port, proto_name, transport_proto
                    ),
                    "error",
                )
                module.log(
                    "Found vulnerability - host: {} port: {} name: {} ".format(
                        service_ip, service_port, vuln_name
                    ),
                    "error",
                )
                module.report_service(
                    service_ip,
                    proto=transport_proto.lower(),
                    port=service_port,
                    name=proto_name.lower(),
                )
                module.report_vuln(
                    service_ip, name=vuln_name, References="Cotopaxi docs"
                )
    except Exception as exc:
        module.log("Error: {}".format(exc), "error")
        logging.error(traceback.format_exc())
        return


if __name__ == "__main__":
    module.run(METADATA, run)
