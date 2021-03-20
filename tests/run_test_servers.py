#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Script for running all test servers in Cotopaxi testbed."""
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
import commands
import subprocess
import os
import psutil
import yaml


def prepare_list_cmd():
    list_cmd = []
    pids = psutil.pids()
    for pid in pids:
        try:
            process = psutil.Process(pid)
            # print("pid  : {}".format(pid))
            # print("name : {}".format(process.name()))
            # print("exe  : {}".format(process.exe()))
            # print("cmd  : {}".format(process.cmdline()))
            list_cmd.append(process.cmdline())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        # print 30*"-"
    return list_cmd


def load_list_servers():
    with open("test_servers.yaml", "r") as stream:
        test_servers = yaml.safe_load(stream)
    return test_servers


# set main directory below
os.chdir("/home/ubuntu")

PROCESSESS = prepare_list_cmd()
# print processes
SERVERS = load_list_servers()
for server in SERVERS:
    server_name = server["name"]
    cmd_split = server["cmd"].replace(":", " ").split()
    server_alive = False
    if cmd_split in PROCESSESS:
        print("Server {} is alive.\n".format(server_name))
        if "check_cmd" in server.keys() and "check_result" in server.keys():
            check_cmd = server["check_cmd"]
            check_result = server["check_result"]
            result = subprocess.check_output(check_cmd.split())
            print("Expected result: {}".format(check_result))
            print("Received result: {}".format(result))
            if check_result in result:
                print("Server {} is responding correctly.\n".format(server_name))
                server_alive = True
            else:
                server_alive = False
                print(
                    "Server {} is NOT responding correctly and will be killed!\n".format(
                        server_name
                    )
                )
                try:
                    if "kill_cmd" in server.keys():
                        kill_cmd = server["kill_cmd"]
                    else:
                        kill_cmd = "screen -S " + server + " -X kill"
                    commands.getoutput(kill_cmd)
                except subprocess.CalledProcessError:
                    pass

        else:
            server_alive = True
    if not server_alive:
        print("Server {} is dead - running up!\n".format(server_name))
        working_directory = server.get("cwd")
        prev_directory = None
        if working_directory:
            prev_directory = os.getcwd()
            os.chdir(working_directory)
        cmd_split = server["cmd"].split()
        # name of screen log is supported from  4.06
        # "-Logfile", "logs/"+server+".log",
        subprocess.check_output(
            ["screen", "-dm", "-L", "-S"]
            + [server["name"] + "_" + str(server["port"])]
            + cmd_split
        )
        # print(["screen", "-dm", "-L", "-Logfile", "logs/"+server+".log", "-S"] + [server] + cmd_split)
        if prev_directory:
            os.chdir(prev_directory)
