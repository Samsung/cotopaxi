# -*- coding: utf-8 -*-
"""Common test functions."""
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

import configparser
import os
import socket
import sys
import time
import traceback
import timeout_decorator
import yaml

from cotopaxi.common_utils import get_local_ip
from cotopaxi.cotopaxi_tester import check_caps

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


def scrap_output(func, data):
    output = ""
    sys.stdout.flush()
    saved_stdout, sys.stdout = sys.stdout, StringIO()
    sys.stderr.flush()
    saved_stderr, sys.stderr = sys.stderr, StringIO()
    try:
        func(data)
    except (SystemExit, Exception) as exception:
        output += str(traceback.extract_stack()) + "\n"
        # output += str(traceback.format_exc()) + "\n"
        # output += ''.join(traceback.format_exception(etype=type(exception), value=exception, tb=exception.__traceback__))
        # output += traceback.format_stack() + "\n"
        output += repr(exception) + "\n"
    finally:
        output += sys.stdout.getvalue().strip() + "\n"
        output += sys.stderr.getvalue().strip() + "\n"
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr
    return output


def load_test_servers():
    print("Loading config for test servers")
    config = configparser.ConfigParser()
    config.read(os.path.dirname(__file__) + "/test_config.ini")
    test_server_ip = config["COMMON"]["DEFAULT_IP"]
    if test_server_ip is None or test_server_ip == "1.1.1.1" or test_server_ip == "":
        print(
            "\nRemote tests are not performed!\nPlease provide address of test server(s) in "
            "cotopaxi/tests/test_config.ini to perform remote tests!\n\n"
        )
    return config


def load_test_servers_list():
    print("Loading list of test servers from YAML")
    with open(os.path.dirname(__file__) + "/test_servers.yaml", "r") as stream:
        test_servers = yaml.safe_load(stream)
        return test_servers
    return None


def poke_tcp_server(server_port):
    for i in range(4):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect(("127.0.0.1", server_port))
            try:
                sock.send("123".encode(encoding="ascii"))
                print("data sent (P3)")
            except (AttributeError, UnicodeDecodeError):
                sock.send(bytes("123"))
                print("data sent (P2)")
            finally:
                sock.close()
                print("socket closed")
        except (socket.timeout, socket.error):
            time.sleep(0.1)


class CotopaxiToolTester(object):
    config = load_test_servers()
    test_servers = load_test_servers_list()
    print("Loaded test servers")
    local_ip = get_local_ip()

    def __init__(self, *args, **kwargs):
        self.main = None

    @timeout_decorator.timeout(5)
    def test_main_help_pos(self):
        output = scrap_output(self.main, ["-h"])
        self.assertIn("optional arguments", output)
        self.assertIn("show this help message and exit", output)


class CotopaxiToolServerTester(CotopaxiToolTester):
    def __init__(self, *args, **kwargs):
        CotopaxiToolTester.__init__(self, *args, **kwargs)
        self.main = None

    @timeout_decorator.timeout(5)
    def test_main_wrong_ip_nonint_neg(self):
        output = scrap_output(self.main, ["a.b.c.d", "40000"])
        self.assertIn("Cannot parse IP address", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_ip_5_octets_neg(self):
        output = scrap_output(self.main, ["1.2.3.4.5", "40000"])
        self.assertIn("Cannot parse IP address", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_port_nonint_neg(self):
        output = scrap_output(self.main, ["10.10.10.10", "aaaaa"])
        self.assertIn("Cannot parse port", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_port_negint_neg(self):
        output = scrap_output(self.main, ["10.10.10.10", "-10"])
        self.assertIn("Cannot parse port", output)

    @timeout_decorator.timeout(5)
    def test_main_wrong_port_bigint_neg(self):
        output = scrap_output(self.main, ["10.10.10.10", "999999"])
        self.assertIn("Port not in range", output)


class CotopaxiToolClientTester(CotopaxiToolTester):
    def __init__(self, *args, **kwargs):
        CotopaxiToolTester.__init__(self, *args, **kwargs)
        self.main = None
