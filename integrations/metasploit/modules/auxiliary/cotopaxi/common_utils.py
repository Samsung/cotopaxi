#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Set of common utils used by different Cotopaxi modules."""
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

import sys
import traceback

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

PARAMETER_RHOSTS = {
    "type": "string",
    "description": "Target destination, IP address or multiple IPs separated"
    ' by coma (e.g. "1.1.1.1,2.2.2.2") or given by CIDR netmask'
    ' (e.g. "10.0.0.0/22") or both',
    "required": True,
    "default": None,
}

PARAMETER_RPORTS = {
    "type": "string",
    "description": (
        "Target ports described by number of port or multiple ports "
        'given by list separated by comas (e.g. "8080,9090") or port range '
        '(e.g. "1000-2000") or mix of both'
    ),
    "required": True,
    "default": "default",
}

PARAMETER_PROTOCOLS = {
    "type": "string",
    "description": "protocol to be tested (UDP includes all UDP-based protocols,"
    " while TCP includes all TCP-based protocols, "
    "ALL includes all supported protocols)",
    "required": False,
    "default": "ALL",
}


# pylint: disable=broad-except
def scrap_output(func, data):
    """Scrap response of executed function from stdout and stderr."""
    output = ""
    sys.stdout.flush()
    saved_stdout, sys.stdout = sys.stdout, StringIO()
    sys.stderr.flush()
    saved_stderr, sys.stderr = sys.stderr, StringIO()
    try:
        func(data)
    except (SystemExit, Exception) as exception:
        output += str(traceback.extract_stack()) + "\n"
        output += repr(exception) + "\n"
    finally:
        output += sys.stdout.getvalue().strip() + "\n"
        output += sys.stderr.getvalue().strip() + "\n"
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr
    return output
