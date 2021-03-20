# -*- coding: utf-8 -*-
"""Set of common utils for MQTT protocol handling."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz, Michał Radwański
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
from hexdump import dehex
from scapy.contrib.mqtt import CONTROL_PACKET_TYPE, MQTT, MQTTConnack, RETURN_CODE

from .common_utils import print_verbose, show_verbose, tcp_sr1
from .protocol_tester import TCPBasedProtocolTester

# MQTT message
# message type = CONNECT
# protocol name = MQTT
# protocol version = 3.1.1
# client ID = 1
MQTT_CONN_MQTT = "100d00044d5154540402003c000131"
MQTT_CONN_MQISDP = (
    "102400064d51497364700302003c000233000000000000000000000000000000000000000000"
)
MQTT_CONN_REJECT = (
    "102400064d51497364700302003c000200000000000000000000000000000000000000000000"
)


def mqtt_request(test_params, out_packet):
    """Send MQTT request to broker and waiting for response."""
    try:
        for i in range(1 + test_params.nr_retries):
            in_data = tcp_sr1(test_params, out_packet)
            in_packet = MQTT(in_data)
            show_verbose(test_params, in_packet)
            if (
                in_packet[MQTT].type in CONTROL_PACKET_TYPE
                and CONTROL_PACKET_TYPE[in_packet[MQTT].type] == "CONNACK"
            ):
                print_verbose(
                    test_params,
                    "MQTT ping {}: in_packet[MQTTConnack].retcode: {}".format(
                        i + 1, RETURN_CODE[in_packet[MQTTConnack].retcode]
                    ),
                )
                return True
    except (socket.timeout, socket.error) as error:
        print_verbose(test_params, error)
    return False


class MQTTTester(TCPBasedProtocolTester):
    """Tester of MQTT protocol."""

    def __init__(self):
        """Construct MQTTTester."""
        TCPBasedProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "MQTT"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "MQ Telemetry Transport"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 1883

    @staticmethod
    def request_parser():
        """Provide Scapy class implementing parsing of protocol requests."""
        return MQTT

    @staticmethod
    def response_parser():
        """Provide Scapy class implementing parsing of protocol responses."""
        return MQTT

    @staticmethod
    def ping(test_params, show_result=False):
        """Check MQTT service availability by sending ping packet and waiting for response."""
        if not test_params:
            return None
        # MQTT ping is using Connect message
        for packet_hex in [MQTT_CONN_MQTT, MQTT_CONN_MQISDP]:
            packet_data = dehex(packet_hex)
            out_packet = MQTT(packet_data)
            if mqtt_request(test_params, out_packet):
                return True
        return False
