# -*- coding: utf-8 -*-
"""Set of common utils for MQTT-SN protocol handling."""
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

import codecs
import socket
import struct
from hexdump import dehex
from scapy.all import UDP
from scapy.contrib.mqtt import MQTT

# from scapy.contrib.mqttsn import MQTTSN

from .common_utils import print_verbose, udp_sr1
from .protocol_tester import UDPBasedProtocolTester

# MQTT-SN message
# message type = Search Gateway (0x01)
# message length = 19
# broadcast radius = 16
MQTTSN_SEARCH_GATEWAY = "130110c0"

# MQTT-SN message
# message type = Gateway Info (0x02)
# message length = 3
# gateway ID = 1
MQTTSN_GATEWAY_INFO = "030201"


def mqttsn_request(test_params, out_packet):
    """Send MQTT-SN request to broker and waiting for response."""
    try:
        for i in range(1 + test_params.nr_retries):
            in_data = udp_sr1(test_params, bytes(out_packet))
            if in_data is None:
                continue
            for response_packet in in_data:
                if response_packet.haslayer(UDP):
                    response_hex = codecs.encode(response_packet[UDP].load, "hex")
                    if response_hex == MQTTSN_GATEWAY_INFO:
                        print_verbose(
                            test_params,
                            "MQTT-SN ping {}: received Gateway Info".format(i + 1),
                        )
                        return True
                    # mqtt = MQTT(response_packet[UDP].load)
                    # mqtt.show()

            # show_verbose(test_params, in_packet)
            # if (
            #     in_packet[MQTT].type in CONTROL_PACKET_TYPE
            #     and CONTROL_PACKET_TYPE[in_packet[MQTT].type] == "CONNACK"
            # ):
            #     print_verbose(
            #         test_params,
            #         "MQTT ping {}: in_packet[MQTTConnack].retcode: {}".format(
            #            i + 1, RETURN_CODE[in_packet[MQTTConnack].retcode]
            #         ),
            #     )
            #     return True
    except struct.error as struct_error:
        print_verbose(test_params, struct_error.message)
    except (socket.timeout, socket.error) as error:
        print_verbose(test_params, error)
    return False


class MQTTSNTester(UDPBasedProtocolTester):
    """Tester of MQTT-SN protocol."""

    def __init__(self):
        """Construct MQTTSNTester."""
        UDPBasedProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "MQTT-SN"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "MQ Telemetry Transport for Sensor Networks"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 1883

    @staticmethod
    def request_parser():
        """Provide Scapy class implementing parsing of protocol requests."""
        # return MQTTSN
        return MQTT

    @staticmethod
    def response_parser():
        """Provide Scapy class implementing parsing of protocol responses."""
        # return MQTTSN
        return MQTT

    @staticmethod
    def ping(test_params, show_result=False):
        """Check MQTT-SN service availability by sending ping packet and waiting for response."""
        if not test_params:
            return None
        # MQTT-SN ping is using Search Gateway message
        for packet_hex in [MQTTSN_SEARCH_GATEWAY]:
            packet_data = dehex(packet_hex)
            out_packet = MQTT(packet_data)
            if mqttsn_request(test_params, out_packet):
                return True
        return False
