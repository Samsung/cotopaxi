# -*- coding: utf-8 -*-
"""Set of common utils for gRPC protocol handling."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#       Author: Jakub Botwicz
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

import socket
import grpc

from .common_utils import print_verbose
from .http2_utils import HTTP2Tester
from .grpc_test_stub_pb2 import PingRequest
from .grpc_test_stub_pb2_grpc import PingServiceStub


class GRPCTester(HTTP2Tester):
    """Tester of gRPC protocol."""

    def __init__(self):
        """Create empty HTTP2Tester object."""
        HTTP2Tester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "gRPC"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "gRPC Remote Procedure Calls"

    @staticmethod
    def ping(test_params, show_result=False):
        """Check gRPC service availability by sending gRPC message and waiting for response."""
        if not test_params:
            return None
        try:
            with grpc.insecure_channel(
                str(test_params.dst_endpoint.ip_addr)
                + ":"
                + str(test_params.dst_endpoint.port)
            ) as channel:
                stub = PingServiceStub(channel)
                stub.ping(PingRequest(request_message="PING"))
        except (socket.timeout, socket.error) as error:
            print_verbose(test_params, error)
        except grpc.RpcError as exc:
            if '"grpc_message":"Method not found!"' in str(exc):
                print_verbose(
                    test_params,
                    "Received gRPC response that triggered exception "
                    "(this is expected due to unknown Protobuf message format): \n"
                    + str(exc),
                )
                return True
            if "ailed to connect to all addresses" not in str(exc):
                print(
                    "[!] Received unknown gRPC message - please report it as an Issue:\n"
                    + str(exc)
                )
        return False

    @staticmethod
    def implements_resource_listing():
        """Return True if this tester implements resource for this protocol."""
        return False
