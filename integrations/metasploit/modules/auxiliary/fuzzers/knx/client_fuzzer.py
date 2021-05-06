#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metasploit wrapper for cotopaxi.client_proto_fuzzer."""
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
from pathlib import Path
import sys
import traceback

try:
    from metasploit import module

    spec = importlib.util.spec_from_file_location(
        "client_proto_fuzzer",
        Path(__file__).absolute().parents[2] / "cotopaxi" / "client_proto_fuzzer.py",
    )
    proto_fuzzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proto_fuzzer)
except ImportError as exc:
    module.log("Error: {}".format(traceback.format_exc()), "error")
    sys.exit("Error: {}".format(traceback.format_exc()), "error")

MODULE_PROTOCOL = Path(__file__).parts[-2].upper()
METADATA = proto_fuzzer.prepare_metadata(MODULE_PROTOCOL)


def run(args):
    """Execute wrapper using provided arguments."""

    args["PROTOCOLS"] = MODULE_PROTOCOL
    proto_fuzzer.run(args)


if __name__ == "__main__":
    module.run(METADATA, run)
