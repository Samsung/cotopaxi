#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Self-check tool for Cotopaxi integration with Metasploit."""
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
import sys
import traceback

try:
    from metasploit import module
    from cotopaxi.common_utils import Protocol
    from cotopaxi.cotopaxi_tester import PROTOCOL_TESTERS

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
    "name": "Self-check tool for Cotopaxi",
    "description": (
        " Checks installation of Cotopaxi components and dependencies."
        "Requires installation of Cotopaxi framework for Python 3!"
    ),
    "authors": ["Jakub Botwicz"],
    "date": "2021-05-03",
    "license": "GPL_LICENSE",
    "references": [{"type": "url", "ref": "https://github.com/Samsung/cotopaxi"},],
    "type": "single_scanner",
    "options": {"PROTOCOLS": common_utils.PARAMETER_PROTOCOLS,},
}


# pylint: disable=broad-except
def run(args):
    """Execute wrapper using provided arguments."""
    if DEPENDENCIES_MISSING:
        logging.error("Module dependency (requests) is missing, cannot continue")
        return args

    logging.error(sys.version_info)
    logging.error(sys.version)


if __name__ == "__main__":
    module.run(METADATA, run)
