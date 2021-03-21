# -*- coding: utf-8 -*-
"""Main module for Cotopaxi."""
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

import logging
import os

# Logging settings for Scapy

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Logging settings for TensorFlow

logging.getLogger("tensorflow").setLevel(logging.ERROR)

#    TF_CPP_MIN_LOG_LEVEL - which has 3 or 4 basic levels
#                          -> low numbers = more messages.
#        0 outputs Information, Warning, Error, and Fatals (default)
#        1 outputs Warning, and above
#        2 outputs Errors and above.
#    TF_CPP_MIN_VLOG_LEVEL - which causes very very many extra Information errors
#                          - really for debugging only -> low numbers = less messages.
#        3 Outputs lots and lots of stuff
#        2 Outputs less
#        1 Outputs even less
#        0 Outputs nothing extra (default)

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["TF_CPP_MIN_VLOG_LEVEL"] = "0"
