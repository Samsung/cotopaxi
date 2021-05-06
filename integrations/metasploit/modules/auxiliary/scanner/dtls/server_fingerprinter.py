#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metasploit wrapper for cotopaxi.server_fingerprinter."""
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
import traceback
from pathlib import Path

try:
    from metasploit import module
    from cotopaxi.common_utils import Protocol
    from cotopaxi.cotopaxi_tester import PROTOCOL_TESTERS
    from cotopaxi.server_fingerprinter import main

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
    "name": "Fingerprinting of network endpoints at given IP and port ranges",
    "description": """
        ...
        (wrapper for cotopaxi.server_fingerprinter)
    """,
    "authors": ["Jakub Botwicz"],
    "date": "2021-03-14",
    "license": "GPL_LICENSE",
    "references": [{"type": "url", "ref": "https://github.com/Samsung/cotopaxi"},],
    "type": "single_scanner",
    "options": {
        "RHOSTS": {
            "type": "string",
            "description": "Target destination, IP address or multiple IPs separated"
            ' by coma (e.g. "1.1.1.1,2.2.2.2") or given by CIDR netmask'
            ' (e.g. "10.0.0.0/22") or both',
            "required": True,
            "default": None,
        },
        "RPORTS": {
            "type": "string",
            "description": "Target ports",
            "required": True,
            "default": None,
        },
    },
}
MODULE_PROTOCOL = "DTLS"


def run(args):
    """Execute wrapper using provided arguments."""
    module.LogHandler.setup(msg_prefix="{} - ".format(args["RHOSTS"]))
    if DEPENDENCIES_MISSING:
        logging.error("Module dependency (requests) is missing, cannot continue")
        return

    try:
        protocols = MODULE_PROTOCOL
        cotopaxi_output = common_utils.scrap_output(
            main, [args["RHOSTS"], args["RPORTS"], "-P", protocols]
        )
        module.log(cotopaxi_output, "error")
        start_index = cotopaxi_output.find("Identified:")
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
                service = service.split(" is using ")
                service_ip = service[0].split(":")[0]
                service_port = service[0].split(":")[1]
                service_name = service[-1]
                transport_proto = (
                    PROTOCOL_TESTERS[getattr(Protocol, proto_name)]
                    .transport_protocol()
                    .__name__
                )
                module.log(
                    "Found service - host: {} port: {} proto: {} over {} using {}".format(
                        service_ip,
                        service_port,
                        proto_name,
                        transport_proto,
                        service_name,
                    ),
                    "error",
                )
                module.report_service(
                    service_ip,
                    proto=transport_proto.lower(),
                    port=service_port,
                    name=proto_name.lower(),
                    info="Server: " + service_name,
                )
    except Exception as exc:
        module.log("Error: {}".format(exc), "error")
        logging.error(traceback.format_exc())
        return


if __name__ == "__main__":
    module.run(METADATA, run)
