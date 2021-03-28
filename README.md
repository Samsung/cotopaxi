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
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cotopaxi)
![LGTM Grade](https://img.shields.io/lgtm/grade/python/github/Samsung/cotopaxi)
![Lines of code](https://img.shields.io/tokei/lines/github/samsung/cotopaxi)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
![GitHub search hit counter](https://img.shields.io/github/search/Samsung/cotopaxi/*)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/Samsung/cotopaxi)
![GitHub issues](https://img.shields.io/github/issues/Samsung/cotopaxi)
<!---![PyPI - Downloads](https://img.shields.io/pypi/dm/cotopaxi) --->
<!---![GitHub all releases](https://img.shields.io/github/downloads/Samsung/cotopaxi/total)--->


Set of tools for security testing of Internet of Things devices using protocols: AMQP, CoAP, DTLS, HTCPCP, HTTP, HTTP/2, gRPC, KNX, mDNS, MQTT, MQTT-SN, QUIC, RTSP, SSDP.

## License:

Cotopaxi uses GNU General Public License, version 2:
https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html

## Disclaimer

Cotopaxi toolkit is intended to be used only for authorized security testing!

Some tools (especially vulnerability tester and protocol fuzzer) can cause some devices or servers to stop acting in the intended way 
-- for example leading to crash or hang of tested entities or flooding with network traffic another entities.

Make sure you have permission from the owners of tested devices or servers before running these tools!

Make sure you check with your local laws before running these tools! 

## Installation

To install minimal Cotopaxi version (without Machine Learning and development tools): 

```
pip install cotopaxi
```

Almost complete installation (without scapy-ssl_tls required for DTLS support):
```
pip install cotopaxi[all]
```

For more detailed documentation about installation see: [Installation Guide](docs/installation.md)

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

Tool                 |     AMQP     |      CoAP    |      DTLS    |    HTCPCP    |      HTTP/2  |     gRPC     |      KNX     |     mDNS     |      MQTT    |    MQTT-SN   |     QUIC     |     RTSP     |     SSDP
---------------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------|--------------
service_ping         |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
server_fingerprinter |&#9744;&#9744;|&#9745;&#9745;|&#9745;&#9745;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;
device_identification|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;
traffic_analyzer     |&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;|&#9744;&#9745;
resource_listing     |&#9744;&#9744;|&#9745;&#9745;|     N/A      |&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9745;&#9745;|&#9744;&#9744;|&#9744;&#9744;|     N/A      |&#9745;&#9745;|&#9745;&#9745;
protocol_fuzzer      |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
client_proto_fuzzer  |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
vulnerability_tester |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
client_vuln_tester   |&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;|&#9745;&#9745;
amplifier_detector   |     N/A      |&#9745;&#9745;|&#9745;&#9745;|     N/A      |     N/A      |     N/A      |     N/A      |&#9745;&#9745;|     N/A      |&#9745;&#9745;|&#9745;&#9745;|     N/A      |&#9745;&#9745;
active_scanner       |&#9744;&#9744;|&#9744;&#9744;|&#9745;&#9745;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;|&#9744;&#9744;

For more detailed documentation of each tool see: [Tools](docs/tools.md)

## Supported vulnerabilites

Vulnerabilities identified by Cotopaxi team, that can be tested using Cotopaxi:
* [BOTAN_000](https://github.com/randombit/botan/issues/1833)
* [COAPTHON_000 (CVE-2018-12679)](https://github.com/Tanganelli/CoAPthon/issues/135)
* [COAPTHON3_000 (CVE-2018-12679)](https://github.com/Tanganelli/CoAPthon3/issues/16)
* [CONTIKI_000 (CVE-2018-19417)](https://github.com/contiki-ng/contiki-ng/issues/600)
* [FLUENTBIT_000 (CVE-2019-9749)](https://github.com/fluent/fluent-bit/issues/1135)
* [IOTIVITY_000 (CVE-2019-9750)](https://jira.iotivity.org/browse/IOT-3267)
* [MADMAZE-HTCPCP_000](https://github.com/madmaze/HTCPCP/issues/13)
* [MATRIXSSL_000](https://github.com/matrixssl/matrixssl/issues/31)
* [MATRIXSSL_001 (CVE-2019-14431)](https://github.com/matrixssl/matrixssl/issues/30)
* [MATRIXSSL_002](https://github.com/matrixssl/matrixssl/issues/32)
* [MATRIXSSL_003](https://github.com/matrixssl/matrixssl/issues/33)
* [SSDP-RESPONDER_000 (CVE-2019-14323)](https://github.com/troglobit/ssdp-responder/issues/1)
* [TINYDTLS_001](https://bugs.eclipse.org/bugs/show_bug.cgi?id=544819)
* [TINYDTLS_002](https://bugs.eclipse.org/bugs/show_bug.cgi?id=544824)
* [TINYDTLS_003](https://www.eclipse.org/lists/tinydtls-dev/msg00206.html)
* [TINYSVCMDNS_002 (CVE-2019-9747)](https://bitbucket.org/geekman/tinysvcmdns/issues/11/denial-of-service-vulnerability-infinite)
* [WAKAAMA_000 (CVE-2019-9004)](https://github.com/eclipse/wakaama/issues/425)
* ZYXEL_000

Other vulnerabilities supported by Cotopaxi:
* [ER_COAP_000](https://github.com/contiki-os/contiki/issues/2240)
* [ER_COAP_001](https://github.com/contiki-os/contiki/issues/2238)
* [ER_COAP_002](https://github.com/contiki-os/contiki/issues/2239)
* [TINYDTLS_000 (CVE-2017-7243)](https://www.cvedetails.com/cve/CVE-2017-7243/)
* [TINYSVCMDNS_000 (CVE-2017-12087)](https://nvd.nist.gov/vuln/detail/CVE-2017-12087)
* [TINYSVCMDNS_001 (CVE-2017-12130)](https://nvd.nist.gov/vuln/detail/CVE-2017-12130)
* [TP-LINK_000 (CVE-2018-18428](https://www.exploit-db.com/exploits/45632)
* [TP-LINK_001](https://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5135.php)
* [FLIR_000](https://www.zeroscience.mk/en/vulnerabilities/ZSL-2018-5492.php)
* [FOSCAM_000 (CVE-2018-19077)](https://sintonen.fi/advisories/foscam-ip-camera-multiple-vulnerabilities.txt)
* [FOSCAM_001 (CVE-2018-19067)](https://sintonen.fi/advisories/foscam-ip-camera-multiple-vulnerabilities.txt)
* [HIKVISION_000 (CVE-2014-4878)](https://blog.rapid7.com/2014/11/19/r7-2014-18-hikvision-dvr-devices-multiple-vulnerabilities/)
* [HIKVISION_001 (CVE-2014-4879)](https://blog.rapid7.com/2014/11/19/r7-2014-18-hikvision-dvr-devices-multiple-vulnerabilities/)
* [HIKVISION_002 (CVE-2014-4880)](https://blog.rapid7.com/2014/11/19/r7-2014-18-hikvision-dvr-devices-multiple-vulnerabilities/)
* [UBIQUITTI_000 (CVE-2019-12727)](https://github.com/X-C3LL/PoC-CVEs/blob/master/Aircam-DoS/Aircam-DoS.py)
* [GSTREAMER_000 (CVE-2019-9928)](https://gstreamer.freedesktop.org/security/sa-2019-0001.html)
* [NETFLIX_000 (CVE-2019-10028)](https://blog.forallsecure.com/forallsecure-uncovers-vulnerability-in-netflix-dial-software)
* [BEWARD_000](https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5509.php)
* [FALCON_000](https://github.com/sbaresearch/advisories/tree/public/2015/knAx_20150101)

New vulnerabilities can be easily added to the database in [vulnerabilities.yaml](./cotopaxi/vulnerabilities/vulnerabilities.yaml) 
and payloads in [cotopaxi/vulnerabilities/<protocol>/<payload.raw>](cotopaxi/vulnerabilities/).

## Known issues / limitations

There are some known issues or limitations caused by using scapy as network library:

* testing services running on the same machine can results in issues occurred by not delivering some packets,
* multiple tools running against the same target can result in interference between them 
(packets may be indicated as a response to another request).

See more at:
https://scapy.readthedocs.io/en/latest/troubleshooting.html#

## Development

For more detailed information about development of Cotopaxi see: [Development guide](docs/development.md)
