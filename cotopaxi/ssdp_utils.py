# -*- coding: utf-8 -*-
"""Set of common utils for SSDP protocol handling."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
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

from scapy.all import UDP

from .common_utils import ssdp_send_query
from .http_utils import HTTPTester

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


class SSDPTester(HTTPTester):
    """Tester of SSDP protocol."""

    def __init__(self):
        """Create empty SSDPTester object."""
        HTTPTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "SSDP"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Simple Service Discovery Protocol"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 1900

    @staticmethod
    def transport_protocol():
        """Provide Scapy class of transport protocol used by this tester (usually TCP or UDP)."""
        return UDP

    @staticmethod
    def ping(test_params, show_result=False):
        """Check SSDP server availability by sending ping packet."""
        if not test_params:
            return None
        ssdp_query_multicast = SSDP_QUERY.format(SSDP_MULTICAST_IPV4, "upnp:rootdevice")
        response = ssdp_send_query(test_params, ssdp_query_multicast)
        if response is None:
            return False
        # print_verbose(test_params, response_packet)
        return "200 OK" in response

    @staticmethod
    def implements_resource_listing():
        """Return True if this tester implements resource for this protocol."""
        return True
