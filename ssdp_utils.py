# -*- coding: utf-8 -*-
"""Set of common utils for SSDP protocol handling."""
#
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Author: Jakub Botwicz (Samsung R&D Poland)
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

from scapy.all import UDP
from scapy.layers.http import HTTPRequest, HTTPResponse

from .common_utils import ssdp_send_query
from .protocol_tester import ProtocolTester

SSDP_QUERY = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST:{}:1900\r\n"
    "ST:{}\r\n"
    "MX:2\r\n"
    'MAN:"ssdp:discover"\r\n'
    "\r\n"
)
SSDP_MULTICAST_IPV4 = "239.255.255.250"
SSDP_MULTICAST_IPV6 = "FF05::C"
SSDP_MULTICAST_PORT = 1900


class SSDPTester(ProtocolTester):
    """Tester of SSDP protocol"""

    def __init__(self):
        ProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provides short (abbreviated) name of protocol"""
        return "SSDP"

    @staticmethod
    def protocol_full_name():
        """Provides full (not abbreviated) name of protocol"""
        return "Simple Service Discovery Protocol"

    @staticmethod
    def default_port():
        """Provides default port used by implemented protocol"""
        return 1900

    @staticmethod
    def transport_protocol():
        """Provides Scapy class of transport protocol used by this tester (usually TCP or UDP)"""
        return UDP

    @staticmethod
    def request_parser():
        """Provides Scapy class implementing parsing of protocol requests"""
        return HTTPRequest

    @staticmethod
    def response_parser():
        """Provides Scapy class implementing parsing of protocol responses"""
        return HTTPResponse

    @staticmethod
    def implements_service_ping():
        """Returns True if this tester implements service_ping for this protocol"""
        return True

    @staticmethod
    def ping(test_params, show_result=False):
        """
        Checks SSDP service availability by sending ping packet and waiting for
        response.
        """
        ssdp_query_multicast = SSDP_QUERY.format(SSDP_MULTICAST_IPV4, "upnp:rootdevice")
        response = ssdp_send_query(test_params, ssdp_query_multicast)
        if response is None:
            return False
        # print_verbose(test_params, response_packet)
        return "200 OK" in response

    @staticmethod
    def implements_fingerprinting():
        """Returns True if this tester implements fingerprinting for this protocol"""
        return False

    @staticmethod
    def implements_resource_listing():
        """Returns True if this tester implements resource for this protocol"""
        return True

    @staticmethod
    def implements_server_fuzzing():
        """Returns True if this tester implements server fuzzing for this protocol"""
        return True

    @staticmethod
    def implements_client_fuzzing():
        """Returns True if this tester implements clients fuzzing for this protocol"""
        return True

    @staticmethod
    def implements_vulnerability_testing():
        """Returns True if this tester implements vulnerability testing for this protocol"""
        return True
