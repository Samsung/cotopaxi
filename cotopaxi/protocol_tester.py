# -*- coding: utf-8 -*-
"""Abstract protocol tester."""
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

import abc
from scapy.all import TCP, UDP

ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})


class ProtocolTester(ABC):
    """Representation of abstract protocol tester."""

    def __init__(self):
        """Create empty ProtocolTester object."""
        pass

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "AGP"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Abstract Generic Protocol"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return -1

    @staticmethod
    def transport_protocol():
        """Provide Scapy class of transport protocol used by this tester (usually TCP or UDP)."""
        return None

    @staticmethod
    def request_parser():
        """Provide Scapy class implementing parsing of protocol requests."""
        return None

    @staticmethod
    def response_parser():
        """Provide Scapy class implementing parsing of protocol responses."""
        return None

    @staticmethod
    def implements_service_ping():
        """Return True if this tester implements service_ping for this protocol."""
        return False

    @staticmethod
    def ping(test_params, show_result=False):
        """Perform service ping for this protocol."""
        if show_result:
            print("Started ping for AGP protocol")
        if not test_params:
            return None
        return False

    @staticmethod
    def implements_fingerprinting():
        """Return True if this tester implements fingerprinting for this protocol."""
        return False

    @staticmethod
    def fingerprint(test_params):
        """Perform server fingerprinting for this protocol."""
        if test_params:
            return ""
        return None

    @staticmethod
    def implements_resource_listing():
        """Return True if this tester implements resource for this protocol."""
        return False

    @staticmethod
    def resource_listing(test_params, resource_list):
        """Perform resource listing for this protocol."""
        if test_params and resource_list:
            return ""
        return None

    @staticmethod
    def implements_server_fuzzing():
        """Return True if this tester implements server fuzzing for this protocol."""
        return False

    @staticmethod
    def implements_client_fuzzing():
        """Return True if this tester implements clients fuzzing for this protocol."""
        return False

    @staticmethod
    def implements_active_scanning():
        """Return True if this tester implements active scanning for this protocol."""
        return False

    @staticmethod
    # pylint: disable=invalid-name
    def implements_vulnerability_testing():
        """Return True if this tester implements vulnerability testing for this protocol."""
        return False


class TCPBasedProtocolTester(ProtocolTester):
    """Tester of any TCP based protocol."""

    def __init__(self):
        """Construct TCPBasedProtocolTester."""
        ProtocolTester.__init__(self)

    @staticmethod
    def transport_protocol():
        """Provide Scapy class of transport protocol used by this tester."""
        return TCP

    @staticmethod
    def implements_service_ping():
        """Return True if this tester implements service_ping for this protocol."""
        return True

    @staticmethod
    def implements_server_fuzzing():
        """Return True if this tester implements server fuzzing for this protocol."""
        return True

    @staticmethod
    def implements_client_fuzzing():
        """Return True if this tester implements clients fuzzing for this protocol."""
        return True

    @staticmethod
    def implements_vulnerability_testing():
        """Return True if this tester implements vulnerability testing for this protocol."""
        return True


class UDPBasedProtocolTester(ProtocolTester):
    """Tester of any UDP based protocol."""

    def __init__(self):
        """Construct TCPBasedProtocolTester."""
        ProtocolTester.__init__(self)

    @staticmethod
    def transport_protocol():
        """Provide Scapy class of transport protocol used by this tester."""
        return UDP

    @staticmethod
    def implements_service_ping():
        """Return True if this tester implements service_ping for this protocol."""
        return True

    @staticmethod
    def implements_server_fuzzing():
        """Return True if this tester implements server fuzzing for this protocol."""
        return True

    @staticmethod
    def implements_client_fuzzing():
        """Return True if this tester implements clients fuzzing for this protocol."""
        return True

    @staticmethod
    def implements_vulnerability_testing():
        """Return True if this tester implements vulnerability testing for this protocol."""
        return True
