# -*- coding: utf-8 -*-
"""Abstract protocol tester."""
#
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz (Samsung R&D Poland)
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

ABC = abc.ABCMeta("ABC", (object,), {"__slots__": ()})


class ProtocolTester(ABC):
    """Representation of abstract protocol tester"""

    def __init__(self):
        pass

    @staticmethod
    def protocol_short_name():
        """Provides short (abbreviated) name of protocol"""
        return "AGP"

    @staticmethod
    def protocol_full_name():
        """Provides full (not abbreviated) name of protocol"""
        return "Abstract Generic Protocol"

    @staticmethod
    def default_port():
        """Provides default port used by implemented protocol"""
        return -1

    @staticmethod
    def transport_protocol():
        """Provides Scapy class of transport protocol used by this tester (usually TCP or UDP)"""
        return None

    @staticmethod
    def request_parser():
        """Provides Scapy class implementing parsing of protocol requests"""
        return None

    @staticmethod
    def response_parser():
        """Provides Scapy class implementing parsing of protocol responses"""
        return None

    @staticmethod
    def implements_service_ping():
        """Returns True if this tester implements service_ping for this protocol"""
        return False

    @staticmethod
    def ping(test_params, show_result=False):
        """Implementation of service ping for this protocol"""
        if show_result:
            print ("Started ping for AGP protocol")
        if not test_params:
            return None
        return False

    @staticmethod
    def implements_fingerprinting():
        """Returns True if this tester implements fingerprinting for this protocol"""
        return False

    @staticmethod
    def fingerprint(test_params):
        """Implementation of server fingerprinter for this protocol"""
        if test_params:
            return ""
        return None

    @staticmethod
    def implements_resource_listing():
        """Returns True if this tester implements resource for this protocol"""
        return False

    @staticmethod
    def resource_listing(test_params, resource_list):
        """Implementation of resource listing for this protocol"""
        if test_params and resource_list:
            return ""
        return None

    @staticmethod
    def implements_server_fuzzing():
        """Returns True if this tester implements server fuzzing for this protocol"""
        return False

    @staticmethod
    def implements_client_fuzzing():
        """Returns True if this tester implements clients fuzzing for this protocol"""
        return False

    @staticmethod
    def implements_active_scanning():
        """Returns True if this tester implements active scanning for this protocol"""
        return False

    @staticmethod
    def implements_vulnerability_testing():
        """Returns True if this tester implements vulnerability testing for this protocol"""
        return False
