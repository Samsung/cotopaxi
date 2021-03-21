```
 .d8888b.           888                                       d8b 
d88P  Y88b          888                                       Y8P 
888    888          888
888         .d88b.  888888 .d88b.  88888b.   8888b.  888  888 888 
888        d88""88b 888   d88""88b 888 "88b     "88b 'Y8bd8P' 888 
888    888 888  888 888   888  888 888  888 .d888888   X88K   888 
Y88b  d88P Y88..88P Y88b. Y88..88P 888 d88P 888  888 .d8""8b. 888 
 "Y8888P"   "Y88P"   "Y888 "Y88P"  88888P"  "Y888888 888  888 888 
                                   888
                                   888
                                   888
```

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
![GitHub top language](https://img.shields.io/github/languages/top/Samsung/cotopaxi)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
![LGTM Grade](https://img.shields.io/lgtm/grade/python/github/Samsung/cotopaxi)
![GitHub search hit counter](https://img.shields.io/github/search/Samsung/cotopaxi/*)

Set of tools for security testing of Internet of Things devices using protocols: AMQP, CoAP, DTLS, HTCPCP, KNX, mDNS, MQTT, MQTT-SN, QUIC, RTSP, SSDP.

## License:

Cotopaxi uses GNU General Public License, version 2:
https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

## Installation using pip:

To install minimal Cotopaxi version (without Machine Learning and development tools): 

```
pip install cotopaxi
```

Minimal version + Machine Learning libraries (numpy, pandas, sklearn, xgboost):
```
pip install cotopaxi[ml]
```

Minimal version + development tools:
```
pip install cotopaxi[dev]
```

Almost complete installation (without scapy-ssl_tls):
```
pip install cotopaxi[all]
```

## Installation from source:

1. Clone code from git:
``` 
git clone https://github.com/Samsung/cotopaxi 
```
2. Enter cotopaxi directory
```
cd cotopaxi 
```
3. Run installer:
```
python setup.py install
```

Optional:

4. Install extras

```
pip install -e .[ml]
```

5. Install scapy-ssl_tls (in case of any problems with scapy and scapy-ssl_tls see section below)

Installation of scapy-ssl_tls is OPTIONAL - required only if you want to test endpoints using DTLS protocol. 

For Python 2.7:
 
(this will install also scapy in 2.4.2)
```
    pip install git+https://github.com/tintinweb/scapy-ssl_tls@ec5714d560c63ea2e0cce713cec54edc2bfa0833
```
For Python 3.6-3.8:
```
    git clone https://github.com/kalidasya/scapy-ssl_tls.git
    cd scapy-ssl_tls
    git checkout py3_update
    python3 setup.py install
```

## Requirements:

Currently Cotopaxi works with Python 2.7.* and with Python 3.6-3.8 (some dependencies like tensorflow do not work on 3.9). 

Installation of required libraries:

### scapy-ssl_tls 

For Python 2.7:
 
(this will install also scapy in 2.4.2)
```
    pip install git+https://github.com/tintinweb/scapy-ssl_tls@ec5714d560c63ea2e0cce713cec54edc2bfa0833
```
Common problems:
* If you encounter error: `error: [Errno 2] No such file or directory: 'LICENSE'`, try repeating command - surprisingly it works.
* If you encounter error: `NameError: name 'os' is not defined` - add missing `import os` to `scapy/layers/ssl_tls.py`.

### Manual installation of other requirements:

For Python 2.7:

```
sudo python2.7 -m pip install -r requirements_python2.txt 
```

For Python 3.6-3.8:

(for installing MINIMAL set of libraries EXCLUDING large Machine Learning libraries (pandas, sklearn, tensorflow, xgboost) required for device_identification and traffic_analyzer)

```
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install -r requirements_minimal.txt 
```

(for installing FULL set of libraries INCLUDING large Machine Learning libraries (pandas, sklearn, tensorflow, xgboost) required for device_identification and traffic_analyzer)
```
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install -r requirements.txt 
```

All required packages for developement of Cotopaxi (including libraries for unit tests) can be installed using requirements_devel.txt file:
```
    pip install -r cotopaxi/requirements_devel.txt
    pre-commit install
```

## Disclaimer

Cotopaxi toolkit is intended to be used only for authorized security testing!

Some tools (especially vulnerability tester and protocol fuzzer) can cause some devices or servers to stop acting in the intended way 
-- for example leading to crash or hang of tested entities or flooding with network traffic another entities.

Make sure you have permission from the owners of tested devices or servers before running these tools!
 
Make sure you check with your local laws before running these tools! 

## Acknowlegments

Machine learning classificator used in the device_identification tool was trained using corpus "IMC 2019 payload dataset" 
provided by authors of the following paper:

Title: Information Exposure for Consumer IoT Devices: A Multidimensional, Network-Informed Measurement Approach
Authors: Jingjing Ren, Daniel J. Dubois, David Choffnes, Anna Maria Mandalari, Roman Kolcun, Hamed Haddadi
Venue: Internet Measurement Conference (IMC) 2019 
URL: https://moniotrlab.ccis.neu.edu/imc19dataset/

We would like to thank above listed authors for sharing this corpus!

## Tools in this package:

* service_ping
* server_fingerprinter
* device_identification
* traffic_analyzer
* resource_listing
* protocol_fuzzer (for fuzzing servers)
* client_proto_fuzzer (for fuzzing clients)
* vulnerability_tester (for testing servers)
* client_vuln_tester (for testing clients)
* amplifier_detector
* active_scanner

Protocols supported by different tools (left box describes working implementation in Python 2 and right one for Python 3): 

Tool                 | AMQP  | CoAP  | DTLS  | HTCPCP |  KNX  |  mDNS | MQTT  |MQTT-SN| QUIC  | RTSP  | SSDP
---------------------|-------|-------|-------|--------|-------|-------|-------|-------|-------|-------|-----
service_ping         |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
server_fingerprinter |       |&#9745;&#9745;|&#9745;&#9745;|        |       |       |       |       |       |       |
device_identification|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;
traffic_analyzer     |&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;
resource_listing     |       |&#9745;&#9745;|  N/A  |        |       |&#9745;&#9745;|       |       |       |&#9745;&#9745;|&#9745;&#9745;
protocol_fuzzer      |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745; |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
client_proto_fuzzer  |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745; |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
vulnerability_tester |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745; |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
client_vuln_tester   |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745; |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
amplifier_detector   |  N/A  |&#9745;&#9745;|&#9745;&#9745;|  N/A   |  N/A   |&#9745;&#9745;|  N/A  |&#9745;&#9745;|&#9745;&#9745;|  N/A  |&#9745;&#9745;
active_scanner       |       |       |&#9745;&#9745;|        |       |       |       |       |       |       |


**cotopaxi.service_ping**

Tool for checking availability of network endpoints at given IP and port ranges
```
usage: python -m cotopaxi.service_ping [-h] [--retries RETRIES] [--timeout TIMEOUT]
                       [--verbose]
                       [--protocol {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                       [--src-ip SRC_IP] [--src-port SRC_PORT]
                       dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {ALL,UDP,TCP,CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested (UDP includes all UDP-based
                        protocols, while TCP includes all TCP-based protocols,
                        ALL includes all supported protocols)
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!) 
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)

```
-------------------------------------------------------------------------------

**cotopaxi.server_fingerprinter**

Tool for software fingerprinting of network endpoints at given IP and port ranges

Currently supported servers:
* CoAP:
    * aiocoap,
    * CoAPthon,
    * FreeCoAP,
    * libcoap,
    * MicroCoAP,
    * Mongoose
    * Wakaama (formerly liblwm2m)
* DTLS:
    *  GnuTLS,
    *  Goldy,
    *  LibreSSL,
    *  MatrixSSL,
    *  mbed TLS,
    *  OpenSSL,
    *  TinyDTLS
```
usage: python -m cotopaxi.server_fingerprinter [-h] [--retries RETRIES] [--timeout TIMEOUT]
                               [--verbose] [--protocol {CoAP,DTLS}]
                               [--src-ip SRC_IP] [--src-port SRC_PORT]
                               [--ignore-ping-check]
                               dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,DTLS}, -P {CoAP,DTLS}
                        protocol to be tested
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)

```
-------------------------------------------------------------------------------

**cotopaxi.device_identification**

Tool for passive identification of IoT devices using captured network traffic

Currently supported devices:
* Amazon Cloudcam
* Amazon Echo Dot
* Amazon Echo Plus
* Amazon Echo Spot
* Amazon Fire TV
* Amcrest Camera
* Anova Sousvide
* Apple TV
* Blink Camera
* Blink Security Hub
* Bosiwo Camera
* D-Llink Mov Sensor
* Flux Bulb
* GE Microwave
* Google Home
* Google Home Mini
* Harman Kardon Allure
* Harman Kardon Invoke
* Honeywell Thermostat
* Insteon Hub
* Lefun Cam
* LG Smart TV
* Luohe Cam
* Magichome Strip
* Microseven Camera
* Nest Thermostat
* Netatmo Weather Station
* Osram Lightify Hub
* Philips Hue (Lightbulb)
* Philips Hue Hub
* Ring Doorbell
* Roku TV
* Samsung Fridge
* Samsung Dryer
* Samsung SmartThings Hub
* Samsung SmartTV
* Samsung Washer
* Sengled Smart Hub
* Smarter Brewer
* Smarter Coffee Machine
* Smarter iKettle
* TP-Link Bulb
* TP-Link Smart Plug
* Wansview Camera
* WeMo Plug
* WiMaker Charger Camera
* Wink Hub 2
* Xiaomi Mi Cam 2
* Xiaomi Mi Robot Cleaner
* Xiaomi Mi Hub
* Xiaomi Mi Rice Cooker
* Xiaomi Mi Power Strip
* Yi Camera
* Zmodo Greet (doorbell)

```
usage: python -m cotopaxi.device_identification usage: [-h] [--verbose] [--min MIN] [--max MAX]
                                [--ip IP] [-S]
                                pcap

Tool for classifying IoT devices based on captured network traffic

positional arguments:
  pcap                  Packet capture file (in PCAP or PCAPNG format) with
                        recorded traffic for device identification

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -V, --debug, -D
                        turn on verbose/debug mode (more messages)
  --min MIN             minimum number of packets to classify device (devices
                        with smaller number will not be classified) (default: 3)
  --max MAX             maximum number of packets used to classify device
                        (default: 1000)
  --ip IP, -I IP        use IP filter to identify device
  -S, --short           display only short result of classification


```

-------------------------------------------------------------------------------

**cotopaxi.traffic_analyzer**

Tool for passive identification of network protocol using captured network traffic

Currently supported protocols:
* AMQP
* BGP
* CMP
* CoAP
* DHCP
* DLNA
* DNS
* DTLS
* EIGRP
* FTP
* GNUTELLA
* GRE
* H323
* HSRP
* HTTP
* HTCPCP
* IGMP
* IPP
* IPsec
* IRC
* KNX
* LLMNR
* mDNS
* MQTT
* MQTT-SN
* MSTP
* NTLM
* NTP
* OCSP
* OSPF
* QUIC
* RADIUS
* RIP
* RPC
* RTSP
* SIP
* SMB
* SMTP
* SNMP
* SSDP
* SSH
* TACACS
* TELNET
* TFTP
* TLS
* VRRP

```
usage: python -m cotopaxi.traffic analyzer usage: [-h] [--verbose] [--min MIN] [--max MAX]
                                [--ip IP] [-S]
                                pcap

Tool for classifying network protocols used in traffic flows

positional arguments:
  pcap                  Packet capture file (in PCAP or PCAPNG format) with
                        recorded traffic for network protocols identification

optional arguments:
  -h, --help            show this help message and exit
  --verbose, -V, --debug, -D
                        turn on verbose/debug mode (more messages)
  --min MIN             minimum number of packets to classify
                        conversation(conversations with smaller number will
                        not be classified) (default: 3)
  --max MAX             maximum number of packets used to classify
                        conversation (default: 1000)
  --ip IP, -I IP        use IP filter to identify protocol
  -S, --short           display only short result of classification


```

-------------------------------------------------------------------------------

**cotopaxi.resource_listing**

Tool for checking availability of resource named url on server at given IP and port ranges.
Sample URL lists are available in the _urls_ directory

```
usage: python -m cotopaxi.resource_listing [-h] [--retries RETRIES] [--timeout TIMEOUT]
                           [--verbose] [--protocol {CoAP,HTTP,mDNS,RTSP,SSDP}]
                           [--src-ip SRC_IP] [--src-port SRC_PORT]
                           [--ignore-ping-check]
                           [--method {GET,POST,PUT,DELETE,ALL} [{GET,POST,PUT,DELETE,ALL} ...]]
                           dest_addr dest_port names_filepath

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both
  names_filepath        path to file with list of names (URLs for CoAP or
                        services for mDNS) to be tested (each name in
                        separated line)

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,HTTP,mDNS,RTSP,SSDP}, -P {CoAP,HTTP,mDNS,RTSP,SSDP}
                        protocol to be tested
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)
  --method {GET,POST,PUT,DELETE,ALL} [{GET,POST,PUT,DELETE,ALL} ...], -M {GET,POST,PUT,DELETE,ALL} [{GET,POST,PUT,DELETE,ALL} ...]
                        methods to be tested (ALL includes all supported
                        methods)

```
-------------------------------------------------------------------------------

**cotopaxi.protocol_fuzzer**

Black-box fuzzer for testing protocol servers

```
usage: python -m cotopaxi.protocol_fuzzer [-h] [--retries RETRIES] [--timeout TIMEOUT]
                          [--verbose]
                          [--protocol {CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                          [--hide-disclaimer] [--src-ip SRC_IP]
                          [--src-port SRC_PORT] [--ignore-ping-check]
                          [--corpus-dir CORPUS_DIR]
                          [--delay-after-crash DELAY_AFTER_CRASH]
                          dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested
  --hide-disclaimer, -HD
                        hides legal disclaimer (shown before starting
                        intrusive tools)
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)
  --corpus-dir CORPUS_DIR, -C CORPUS_DIR
                        path to directory with fuzzing payloads (corpus) (each
                        payload in separated file)
  --delay-after-crash DELAY_AFTER_CRASH, -DAC DELAY_AFTER_CRASH
                        number of seconds that fuzzer will wait after crash
                        for respawning tested server
```

-------------------------------------------------------------------------------

**cotopaxi.client_proto_fuzzer**

Black-box fuzzer for testing protocol clients

```
usage: (sudo) python -m cotopaxi.client_proto_fuzzer [-h] [--server-ip SERVER_IP]
                              [--server-port SERVER_PORT] [--verbose]
                              [--protocol {CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                              [--corpus-dir CORPUS_DIR]

(sudo required for listening on ports below 1024)

optional arguments:
  -h, --help            show this help message and exit
  --server-ip SERVER_IP, -SI SERVER_IP
                        IP address, that will be used to set up tester server
  --server-port SERVER_PORT, -SP SERVER_PORT
                        port that will be used to set up server
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,DTLS,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested
  --corpus-dir CORPUS_DIR, -C CORPUS_DIR
                        path to directory with fuzzing payloads (corpus) (each
                        payload in separated file)
```

-------------------------------------------------------------------------------

**cotopaxi.vulnerability_tester**

Tool for checking vulnerability of network endpoints at given IP and port ranges
```
usage: python -m cotopaxi.vulnerability_tester -h
usage: vulnerability_tester.py [-h] [--retries RETRIES] [--timeout TIMEOUT]
                               [--verbose]
                               [--protocol {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                               [--hide-disclaimer] [--src-ip SRC_IP]
                               [--src-port SRC_PORT] [--ignore-ping-check]
                               [--vuln {ALL,BEWARD_000,BOTAN_000,...} ...]]
                               [--cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]]
                               [--list]
                               dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {ALL,UDP,TCP,CoAP,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested (UDP includes all UDP-based
                        protocols, while TCP includes all TCP-based protocols,
                        ALL includes all supported protocols)
  --hide-disclaimer, -HD
                        hides legal disclaimer (shown before starting
                        intrusive tools)
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)
  --vuln {ALL,BEWARD_000,BOTAN_000,...} ...]
                        list of vulnerabilities to be tested (by SOFT_NUM id)
  --cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]
                        list of vulnerabilities to be tested (by CVE id)
  --list, -L            display lists of all vulnerabilities supported by this
                        tool with detailed description

```
-------------------------------------------------------------------------------

**cotopaxi.client_vuln_tester**

Tool for checking vulnerability of network clients connecting to server provided by this tool

```
usage: (sudo) python -m cotopaxi.client_vuln_tester [-h] [--server-ip SERVER_IP]
                             [--server-port SERVER_PORT] [--verbose]
                             [--protocol {CoAP,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}]
                             [--vuln {ALL,BEWARD_000,BOTAN_000,...} ...]]
                             [--cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]]
                             [--list]

(sudo required for listening on ports below 1024)
optional arguments:
  -h, --help            show this help message and exit
  --server-ip SERVER_IP, -SI SERVER_IP
                        IP address, that will be used to set up tester server
  --server-port SERVER_PORT, -SP SERVER_PORT
                        port that will be used to set up server
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {CoAP,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}, -P {CoAP,HTCPCP,HTTP,KNX,mDNS,MQTT,QUIC,RTSP,SSDP}
                        protocol to be tested
  --vuln {ALL,BEWARD_000,BOTAN_000,...} ...]
                        list of vulnerabilities to be tested (by SOFT_NUM id)
  --cve {ALL,CVE-2014-4878,CVE-2014-4879,...} ...]
                        list of vulnerabilities to be tested (by CVE id)
  --list, -L            display lists of all vulnerabilities supported by this
                        tool with detailed description

```

-------------------------------------------------------------------------------

**cotopaxi.amplifier_detector**

Tool for detection of network devices amplifying reflected traffic
by observing size of incoming and outgoing size of packets
```
usage: sudo python -m cotopaxi.amplifier_detector [-h] [--port PORT] [--nr NR] [--verbose] dest_addr

positional arguments:
  dest_addr               destination IP address

optional arguments:
  -h, --help            show this help message and exit
  --interval INTERVAL, -I INTERVAL
                        minimal interval in sec between displayed status
                        messages (default: 1 sec)
  --port PORT, --dest_port PORT, -P PORT
                        destination port
  --nr NR, -N NR        number of packets to be sniffed (default: 9999999)
  --verbose, -V, --debug, -D
                        turn on verbose/debug mode (more messages)

```

-------------------------------------------------------------------------------

**cotopaxi.active_scanner**

Tool for checking security properties of network endpoints at given IP and port ranges

```
usage: python -m cotopaxi.active_scanner [-h] [--retries RETRIES] [--timeout TIMEOUT]
                         [--verbose] [--protocol {DTLS}] [--src-ip SRC_IP]
                         [--src-port SRC_PORT] [--ignore-ping-check]
                         dest_addr dest_port

positional arguments:
  dest_addr             destination hostname, IP address or multiple IPs
                        separated by coma (e.g. '1.1.1.1,2.2.2.2') or given by
                        CIDR netmask (e.g. '10.0.0.0/22') or both

  dest_port             destination port or multiple ports given by list
                        separated by coma (e.g. '8080,9090') or port range
                        (e.g. '1000-2000') or both

optional arguments:
  -h, --help            show this help message and exit
  --retries RETRIES, -R RETRIES
                        number of retries
  --timeout TIMEOUT, -T TIMEOUT
                        timeout in seconds
  --verbose, -V, --debug, -D
                        Turn on verbose/debug mode (more messages)
  --protocol {DTLS}, -P {DTLS}
                        protocol to be tested
  --src-ip SRC_IP, -SI SRC_IP
                        source IP address (return result will not be
                        received!)
  --src-port SRC_PORT, -SP SRC_PORT
                        source port (if not specified random port will be
                        used)
  --ignore-ping-check, -Pn
                        ignore ping check (treat all ports as alive)

```


-------------------------------------------------------------------------------

## Known issues / limitations

There are some known issues or limitations caused by using scapy as network library:

* testing services running on the same machine can results in issues occurred by not delivering some packets,
* multiple tools running against the same target can result in interference between them 
(packets may be indicated as a response to another request).


See more at:
https://scapy.readthedocs.io/en/latest/troubleshooting.html#

## Source code quality

Before uploading your contribution using github Pull Request please check your code using tools listed below:

```
black -t py36 cotopaxi
black -t py36 tests

pydocstyle cotopaxi

python -m pylint cotopaxi --rcfile=.pylintrc
python -m pylint tests --rcfile=tests/.pylintrc

bandit -r cotopaxi
```

## Unit tests

To run all unit tests using unittest use (from upper cotopaxi dir):
```
    sudo python -m unittest discover -v
```

To run all unit tests using unittest with coverage analysis run (from upper cotopaxi dir):
```
    sudo coverage run --source cotopaxi -m unittest discover
    coverage html
    firefox htmlcov/index.html
```

To run all unit tests using pytest with coverage analysis and branch analysis run (from upper cotopaxi dir):

```
    sudo python2.7 -m coverage run --source cotopaxi --branch -m pytest -v
    sudo python2.7 -m coverage html
    firefox htmlcov/index.html

    sudo python3 -m coverage run --source cotopaxi --branch -m pytest -v
    sudo python3 -m coverage html
    firefox htmlcov/index.html
```

To run unit tests for one of tools run (from upper cotopaxi dir):
```
    python -m tests.test_active_scanner
    sudo python -m tests.test_amplifier_detector
    python -m tests.test_client_proto_fuzzer
    python -m tests.test_device_identification
    python -m tests.test_traffic_analyzer
    python -m tests.test_protocol_fuzzer
    sudo python -m tests.test_resource_listing
    python -m tests.test_server_fingerprinter
    python -m tests.test_service_ping
    python -m tests.test_vulnerability_tester
```

Most of the tests are performed against remote tests servers and require preparing test environment, 
providing settings in tests/test_config.ini and tests/test_servers.yaml.

