#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metasploit wrapper for cotopaxi.resource_listing."""
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
    from cotopaxi.protocol_fuzzer import main

    spec = importlib.util.spec_from_file_location(
        "common_utils", Path(__file__).absolute().parents[0] / "common_utils.py",
    )
    common_utils = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common_utils)

    DEPENDENCIES_MISSING = False
except ImportError:
    module.log("Error: {}".format(traceback.format_exc()), "error")
    DEPENDENCIES_MISSING = True


METADATA = {
    "name": "Tool for checking availability of resource on server at given IP and port ranges",
    "description": """
        ...
        (wrapper for cotopaxi.resource_listing)
    """,
    "authors": ["Jakub Botwicz"],
    "date": "2021-03-27",
    "license": "GPL_LICENSE",
    "references": [{"type": "url", "ref": "https://github.com/Samsung/cotopaxi"},],
    "type": "single_scanner",
    "options": {
        "RHOSTS": common_utils.PARAMETER_RHOSTS,
        "RPORTS": common_utils.PARAMETER_RPORTS,
        "PROTOCOLS": common_utils.PARAMETER_PROTOCOLS,
        "PATH_LIST": {
            "type": "string",
            "description": (
                "path to path to file with list of names (URLs for CoAP or"
                "services for mDNS) to be tested (each name in"
                "separated line)"
            ),
            "required": True,
            "default": False,
        },
        "IGNORE_PING_CHECK": {
            "type": "bool",
            "description": "ignore ping check (treat all endpoints as alive)",
            "required": False,
            "default": False,
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
        parameters = [args["RHOSTS"], args["RPORTS"]]
        if args["PROTOCOLS"]:
            parameters += ["-P", args["PROTOCOLS"]]
        if args["IGNORE_PING_CHECK"]:
            parameters += ["--ignore-ping-check"]
        cotopaxi_output = common_utils.scrap_output(main, parameters)
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
