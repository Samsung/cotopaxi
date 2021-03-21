# -*- coding: utf-8 -*-
"""Scanner for identifying issues in DTLS servers or traffic."""
#
#    Copyright (C) 2021 Cotopaxi Contributors. All Rights Reserved.
#    Copyright (C) 2020 Samsung Electronics. All Rights Reserved.
#       Authors: Jakub Botwicz,
#                tintinweb@oststrom.com <github.com/tintinweb>
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

from __future__ import print_function
from collections import namedtuple
import concurrent.futures
import socket
import sys
from scapy.all import bind_layers, IP, sniff, UDP

try:
    from scapy_ssl_tls.ssl_tls import (
        DTLSRecord,
        DTLSClientHello,
        DTLSHandshake,
        DTLSHelloVerify,
        TLSHeartBeat,
        EnumStruct,
        SSLv2_CIPHER_SUITES,
        TLSAlert,
        TLS_HANDSHAKE_TYPES,
        TLSChangeCipherSpec,
        TLSContentType,
        TLSCiphertext,
        TLSHelloRequest,
        TLSHandshakeType,
        TLSClientHello,
        TLSHelloRetryRequest,
        TLSExtRenegotiationInfo,
        TLSExtSignatureAlgorithms,
        TLS13Certificate,
        TLSCertificateList,
        TLSServerKeyExchange,
        TLSServerHelloDone,
        TLSClientKeyExchange,
        TLSFinished,
        TLSSessionTicket,
        TLSCertificateRequest,
        TLSCertificateVerify,
        TLSEncryptedExtensions,
        TLSAlertDescription,
        TLSExtHeartbeat,
        TLSHeartbeatMode,
        TLSSignatureScheme,
        TLSExtension,
        TLSCipherSuite,
        TLS_SIGNATURE_SCHEMES,
    )
    import scapy_ssl_tls.ssl_tls_keystore as tlsk
except (ImportError, ModuleNotFoundError):
    from .common_utils import SCAPY_SSL_TLS_NOT_INSTALLED

    sys.exit(SCAPY_SSL_TLS_NOT_INSTALLED)

from .common_utils import print_verbose, Protocol, show_verbose
from .cotopaxi_tester import CotopaxiTester
from .dtls_utils import (
    ENUM_DTLS_VERSIONS,
    DTLS,
    DTLSClient,
    DTLSServerHello,
    DTLS_VERSIONS,
    DTLS_CIPHER_SUITES,
    DTLSHandshakes,
    DTLS_COMPRESSION_METHODS,
)
from .service_ping import service_ping

TLS_HANDSHAKE_TYPES.update({0x3: "hello_verify_request"})
ENUM_DTLS_HANDSHAKE_TYPES = EnumStruct(TLS_HANDSHAKE_TYPES)

# bind records
bind_layers(
    DTLSRecord, TLSChangeCipherSpec, {"content_type": TLSContentType.CHANGE_CIPHER_SPEC}
)
bind_layers(
    DTLSRecord, TLSCiphertext, {"content_type": TLSContentType.APPLICATION_DATA}
)
bind_layers(DTLSRecord, TLSHeartBeat, {"content_type": TLSContentType.HEARTBEAT})
bind_layers(DTLSRecord, TLSAlert, {"content_type": TLSContentType.ALERT})
bind_layers(DTLSRecord, DTLSHandshake, {"content_type": TLSContentType.HANDSHAKE})

# bind handshakes
bind_layers(DTLSHandshake, DTLSClientHello, {"type": TLSHandshakeType.CLIENT_HELLO})
bind_layers(
    DTLSHandshake,
    DTLSHelloVerify,
    {"type": ENUM_DTLS_HANDSHAKE_TYPES.HELLO_VERIFY_REQUEST},
)
bind_layers(DTLSHandshake, TLSHelloRequest, {"type": TLSHandshakeType.HELLO_REQUEST})
bind_layers(DTLSHandshake, TLSClientHello, {"type": TLSHandshakeType.CLIENT_HELLO})
bind_layers(DTLSHandshake, DTLSServerHello, {"type": TLSHandshakeType.SERVER_HELLO})
bind_layers(
    DTLSHandshake, TLSHelloRetryRequest, {"type": TLSHandshakeType.HELLO_RETRY_REQUEST}
)
bind_layers(DTLSHandshake, TLSCertificateList, {"type": TLSHandshakeType.CERTIFICATE})
bind_layers(
    DTLSHandshake, TLSServerKeyExchange, {"type": TLSHandshakeType.SERVER_KEY_EXCHANGE}
)
bind_layers(
    DTLSHandshake, TLSServerHelloDone, {"type": TLSHandshakeType.SERVER_HELLO_DONE}
)
bind_layers(
    DTLSHandshake, TLSClientKeyExchange, {"type": TLSHandshakeType.CLIENT_KEY_EXCHANGE}
)
bind_layers(DTLSHandshake, TLSFinished, {"type": TLSHandshakeType.FINISHED})
bind_layers(
    DTLSHandshake, TLSSessionTicket, {"type": TLSHandshakeType.NEWSESSIONTICKET}
)
bind_layers(
    DTLSHandshake, TLSCertificateRequest, {"type": TLSHandshakeType.CERTIFICATE_REQUEST}
)
bind_layers(
    DTLSHandshake, TLSCertificateVerify, {"type": TLSHandshakeType.CERTIFICATE_VERIFY}
)
bind_layers(
    DTLSHandshake,
    TLSEncryptedExtensions,
    {"type": TLSHandshakeType.ENCRYPTED_EXTENSIONS},
)


class DTLSInfo(object):
    """DTLSInfo passively evaluates the traffic and generates events/warning."""

    # https://en.wikipedia.org/wiki/RSA_numbers
    RSA_MODULI_KNOWN_FACTORED = (
        # RSA-100
        int(
            "1522605027922533360535618378132637429718068114961380688657908494580122963258952897654"
            "000350692006139"
        ),
        # RSA-110
        int(
            "3579423417972586877499180783256845540300377802422822619353290819048467025236467741151"
            "3516111204504060317568667"
        ),
        # RSA-120
        int(
            "2270104812954373633342599609474936688958753364660847800381732582470091626757797353897"
            "91151574049166747880487470296548479"
        ),
        # RSA-129
        int(
            "1143816257578888676692357799761466120102182967212423625625618429357069352457338978305"
            "97123563958705058989075147599290026879543541"
        ),
        # RSA-130
        int(
            "1807082088687404805951656164405905566278102516769401349170127021450056662540244048387"
            "341127590812303371781887966563182013214880557"
        ),
        # RSA-140
        int(
            "2129024631825875754749788201627151749780670396327721627823338321538194998405649591136"
            "6573853021918316783107387995317230889569230873441936471"
        ),
        # RSA-150
        int(
            "1550898124783484405096067543700118617706545458309954306554669457743126327034634659543"
            "63335027577729025391453996787414027003501631772186840890795964683"
        ),
        # RSA-155
        int(
            "1094173864157052742180970732204035761200373294544920599091384213147634998428893478471"
            "7997257891267332497625752899781833797076537244027146743531593354333897"
        ),
        # RSA-160
        int(
            "2152741102718889701896015201312825429257773588845675980170497676778133145218859135673"
            "011059773491059602497907111585214302079314665202840140619946994927570407753"
        ),
        # RSA-170
        int(
            "2606262368413984492152987926667443219708592538048640641616478519185999962854206936145"
            "0283931914514618683512198164805919882053057222974116478065095809832377336510711545759"
        ),
        # RSA-576
        int(
            "1881988129206079638386972394616504398071635633794173827007633564229888597152346654853"
            "1906060650474304531738801130339671619969232120573403187955065699622130516875930765025"
            "7059"
        ),
        # RSA-180
        int(
            "1911479277189866096892294666314546498129862462766673548641885036388072607034367990587"
            "7620136513516127813425829612810920004670291298456875280033022177775277395740454049570"
            "7851421041"
        ),
        # RSA-190
        int(
            "1907556405060696491061450432646028861081179759533184460647975622318915025587184175754"
            "0549761551215932934922604641526300932385092466032074171247261215808581859859389469454"
            "90481721756401423481"
        ),
        # RSA-640
        int(
            "3107418240490043721350750035888567930037346022842727545720161948823206440518081504556"
            "3468296717232867824379162728380334154710731085019195485290073377248227835257423864540"
            "14691736602477652346609"
        ),
        # RSA-200
        int(
            "2799783391122132787082946763872260162107044678695542853756000992932612840010760934567"
            "1052955360856061822351910951365788637105954482006576775098580557613579098734950144178"
            "863178946295187237869221823983"
        ),
        # RSA-210
        int(
            "2452466449002782119765176635730880184670267876783327597434144517150616008300385872169"
            "5220839933207154910362682719167986407977672324300560059203563124656121846581790410013"
            "1859299619933817012149335034875870551067"
        ),
        # RSA-704
        int(
            "7403756347956171282804679609742957314259318888923128908493623263897276503402826627689"
            "1996419625117843995894330502127585370118968098286733173273108930900552505116877063299"
            "072396380786710086096962537934650563796359"
        ),
        # RSA-768
        int(
            "1230186684530117755130494958384962720772853569595334792197322452151726400507263657518"
            "7452021997864693899564749427740638459251925573263034537315482685079170261221429134616"
            "70429214311602221240479274737794080665351419597459856902143413"
        ),
    )

    def __init__(self, test_params):
        """Construct DTLSSInfo."""
        self.test_params = test_params
        self.history = []
        self.events = []
        self.info = namedtuple("info", ["client", "server"])
        self.info.client = namedtuple(
            "client",
            [
                "versions",
                "ciphers",
                "compressions",
                "preferred_ciphers",
                "sessions_established",
                "heartbeat",
                "extensions",
            ],
        )
        self.info.client.versions = set([])
        self.info.client.ciphers = set([])
        self.info.client.compressions = set([])
        self.info.client.preferred_ciphers = set([])
        self.info.client.sessions_established = 0
        self.info.client.heartbeat = None
        self.info.client.extensions = set([])
        self.info.server = namedtuple(
            "server",
            [
                "versions",
                "ciphers",
                "compressions",
                "sessions_established",
                "fallback_scsv",
                "heartbeat",
                "extensions",
            ],
        )
        self.info.server.versions = set([])
        self.info.server.ciphers = set([])
        self.info.server.compressions = set([])
        self.info.server.sessions_established = 0
        self.info.server.fallback_scsv = None
        self.info.server.heartbeat = None
        self.info.server.certificates = set([])
        self.info.server.extensions = set([])

    def __str__(self):
        """Return DTLSInfo statistics."""
        return """<DTLSInfo
        packets.processed: %s

        client.versions: %s
        client.ciphers: %s
        client.compressions: %s
        client.preferred_ciphers: %s
        client.sessions_established: %s
        client.heartbeat: %s

        server.versions: %s
        server.ciphers: %s
        server.compressions: %s
        server.sessions_established: %s
        server.fallback_scsv: %s
        server.heartbeat: %s

        server.certificates: 
------------- CERTLIST START --------------
%s
------------- CERTLIST STOP  --------------
>
        """ % (
            len(self.history),
            self.info.client.versions,
            self.info.client.ciphers,
            self.info.client.compressions,
            self.info.client.preferred_ciphers,
            self.info.client.sessions_established,
            self.info.client.heartbeat,
            self.info.server.versions,
            self.info.server.ciphers,
            self.info.server.compressions,
            self.info.server.sessions_established,
            self.info.server.fallback_scsv,
            self.info.server.heartbeat,
            ("-----\n").join(self.info.server.certificates),
        )

    def report_issue(self, description, data):
        """Append description of issue to set of issues."""
        self.test_params.test_stats.active_endpoints[Protocol.DTLS].append(
            "{}:{} - vuln: {}".format(
                self.test_params.dst_endpoint.ip_addr,
                self.test_params.dst_endpoint.port,
                description,
            )
        )
        self.events.append((description, data))

    def check_sloth(self, dtlsinfo):
        """Obvious SLOTH check.

        Does not detect implementation errors that allow MD5 even
           though not announced. Makes only sense for ClientHello.
        """
        exts = [
            ext
            for ext in dtlsinfo.extensions
            if ext.haslayer(TLSExtSignatureAlgorithms)
        ]
        for ext in exts:
            for alg in ext.algs:
                if alg in (
                    TLSSignatureScheme.RSA_MD5,
                    TLSSignatureScheme.RSA_PKCS1_SHA1,
                    TLSSignatureScheme.ECDSA_MD5,
                    TLSSignatureScheme.ECDSA_SECP256R1_SHA256,
                    TLSSignatureScheme.DSA_MD5,
                    TLSSignatureScheme.DSA_SHA1,
                ):
                    self.report_issue(
                        "SLOTH - %s announces capability of signature/hash algorithm: %s"
                        % (dtlsinfo.__name__, TLS_SIGNATURE_SCHEMES.get(alg)),
                        TLS_SIGNATURE_SCHEMES.get(alg),
                    )

    def check_public_key(self, dtlsinfo):
        """Check public keys in DTLS sessions."""
        try:
            for certlist in dtlsinfo.certificates:
                for cert in certlist.certificates:
                    try:
                        keystore = tlsk.RSAKeystore.from_der_certificate(str(cert.data))
                        pubkey = keystore.public
                        pubkey_size = pubkey.size_in_bits()
                        if pubkey_size < 2048:
                            self.report_issue(
                                "INSUFFICIENT SERVER CERT PUBKEY SIZE - 2048 >= %d bits"
                                % pubkey_size,
                                cert,
                            )
                        if pubkey_size % 2048 != 0:
                            self.report_issue(
                                "SUSPICIOUS SERVER CERT PUBKEY SIZE - "
                                "%d not a multiple of 2048 bits" % pubkey_size,
                                cert,
                            )
                        if pubkey.n in self.RSA_MODULI_KNOWN_FACTORED:
                            self.report_issue(
                                "SERVER CERT PUBKEY FACTORED - trivial private_key recover"
                                "y possible due to known factors n = p x q. See https://en"
                                ".wikipedia.org/wiki/ RSA_numbers | grep %s" % pubkey.n,
                                cert,
                            )
                    except ValueError:
                        pass
        except AttributeError:
            pass  # tlsinfo.client has no attribute certificates

    def check_cipher(self, cipher_namelist, cipher):
        """Check whether particular cipher is listed."""
        tmp = [c for c in cipher_namelist if isinstance(c, str) and cipher in c.upper()]
        if tmp:
            self.report_issue("CIPHERS - {} ciphers enabled".format(cipher), tmp)

    def get_events(self):
        """Return list of all reported events."""
        events = []
        for dtlsinfo in (self.info.client, self.info.server):
            # test CRIME - compressions offered?
            tmp = dtlsinfo.compressions.copy()
            if 0 in tmp:
                tmp.remove(0)
            if tmp:
                self.report_issue(
                    "CRIME - %s supports compression" % dtlsinfo.__name__,
                    dtlsinfo.compressions,
                )
            # test RC4
            cipher_namelist = [
                DTLS_CIPHER_SUITES.get(c, "SSLv2_%s" % SSLv2_CIPHER_SUITES.get(c, c))
                for c in dtlsinfo.ciphers
            ]

            tmp = [
                c
                for c in cipher_namelist
                if isinstance(c, str) and "SSLV2" in c.upper() and "EXP" in c.upper()
            ]
            if tmp:
                self.report_issue("DROWN - SSLv2 with EXPORT ciphers enabled", tmp)
            tmp = [
                c for c in cipher_namelist if isinstance(c, str) and "EXP" in c.upper()
            ]
            if tmp:
                self.report_issue("CIPHERS - Export ciphers enabled", tmp)
            self.check_cipher(cipher_namelist, "RC4")
            self.check_cipher(cipher_namelist, "MD2")
            self.check_cipher(cipher_namelist, "MD4")
            self.check_cipher(cipher_namelist, "MD5")
            tmp = [
                c
                for c in cipher_namelist
                if isinstance(c, str) and "RSA_EXP" in c.upper()
            ]
            if tmp:
                # only check DHE EXPORT for now. we might want to add DH1024 here.
                self.report_issue(
                    "FREAK - server supports RSA_EXPORT cipher suites", tmp
                )
            tmp = [
                c
                for c in cipher_namelist
                if isinstance(c, str) and "DHE_" in c.upper() and "EXPORT_" in c.upper()
            ]
            if tmp:
                # only check DHE EXPORT for now. we might want to add DH1024 here.
                self.report_issue(
                    "LOGJAM - server supports weak DH-Group (512) (DHE_*_EXPORT) cipher suites",
                    tmp,
                )
            self.check_sloth(dtlsinfo)
            self.check_public_key(dtlsinfo)
            if TLSHeartbeatMode.PEER_ALLOWED_TO_SEND == dtlsinfo.heartbeat:
                self.report_issue(
                    "HEARTBEAT - enabled (non conclusive heartbleed) ",
                    dtlsinfo.versions,
                )

        if self.info.server.fallback_scsv:
            self.report_issue(
                "DOWNGRADE / POODLE - FALLBACK_SCSV honored "
                "(alert.inappropriate_fallback seen)",
                self.info.server.fallback_scsv,
            )
        events.extend(self.events)
        return events

    def insert(self, pkt, client=None):
        """Insert packet into processing queue."""
        self._process(pkt, client=client)

    def process_record(self, pkt, record, client=None):
        """Process DTLS record."""
        print_verbose(self.test_params, "------------- RECORD START --------------")
        show_verbose(self.test_params, record)
        print_verbose(self.test_params, "------------- RECORD STOP --------------")
        if client or record.haslayer(DTLSClientHello):
            dtlsinfo = self.info.client
        elif (
            not client
            or record.haslayer(DTLSServerHello)
            or record.haslayer(DTLSHelloVerify)
        ):
            dtlsinfo = self.info.server

        if not pkt.haslayer(TLSAlert) and pkt.haslayer(DTLSRecord):
            print_verbose(self.test_params, "Updating version from DTLSRecord")
            dtlsinfo.versions.add(pkt[DTLSRecord].version)

        if record.haslayer(DTLSClientHello):
            print_verbose(self.test_params, "Updating stats for DTLSClientHello")
            dtlsinfo.ciphers.update(record[DTLSClientHello].cipher_suites)
            dtlsinfo.compressions.update(record[DTLSClientHello].compression_methods)
            if record[DTLSClientHello].cipher_suites:
                dtlsinfo.preferred_ciphers.add(pkt[DTLSClientHello].cipher_suites[0])
            dtlsinfo.extensions.update(record[DTLSClientHello].extensions)

        if record.haslayer(DTLSServerHello):
            print_verbose(self.test_params, "Updating stats for DTLSServerHello")
            dtlsinfo.ciphers.add(record[DTLSServerHello].cipher_suite)
            dtlsinfo.compressions.add(record[DTLSServerHello].compression_method)
            if record.haslayer(TLSExtHeartbeat):
                dtlsinfo.heartbeat = record[TLSExtHeartbeat].mode
            dtlsinfo.extensions.update(record[DTLSServerHello].extensions)

        if record.haslayer(TLSCertificateList):
            print_verbose(self.test_params, "Updating stats for TLSCertificateList")
            dtlsinfo.certificates.add(record[TLSCertificateList].show(dump=True))

        if record.haslayer(TLSFinished):
            print_verbose(self.test_params, "Updating stats for TLSFinished")
            dtlsinfo.session.established += 1

        if record.haslayer(DTLSHandshake):
            print_verbose(self.test_params, "Updating stats for DTLSHandshake")
            dtlsinfo.versions.add(pkt[DTLSRecord].version)
            # if record[DTLSHandshake].type == TLSHandshakeType.SERVER_HELLO
            # and record[DTLSHandshake].load:
            #     print("Updating stats for DTLSServerHello - own parse")
            #     dtls_server_hello = DTLSServerHello(record[DTLSHandshake].load)
            #     dtlsinfo.ciphers.add(dtls_server_hello.cipher_suite)
            #     dtlsinfo.compressions.add(dtls_server_hello.compression_method)
            #     if dtls_server_hello.haslayer(TLSExtHeartbeat):
            #         dtlsinfo.heartbeat = dtls_server_hello[TLSExtHeartbeat].mode
            #     dtlsinfo.extensions.update(dtls_server_hello.extensions)

        if (
            not client
            and record.haslayer(TLSAlert)
            and record[TLSAlert].description
            == TLSAlertDescription.INAPPROPRIATE_FALLBACK
        ):
            dtlsinfo.fallback_scsv = True

    def _process(self, pkt, client=None):
        if not pkt or not (pkt.haslayer(DTLSRecord)):
            return
        print_verbose(self.test_params, "------------- START --------------")
        show_verbose(self.test_params, pkt)
        print_verbose(self.test_params, "------------- STOP --------------")
        if pkt.haslayer(DTLS):
            records = pkt[DTLS].records
        else:
            records = [pkt]

        for record in records:
            self.process_record(pkt, record, client)
        # track packet
        self.history.append(pkt)


class DTLSScanner(object):
    """Generate DTLS probe traffic."""

    def __init__(self, test_params, workers=10):
        """Construct empty DTLSScanner object."""
        self.workers = workers
        self.capabilities = DTLSInfo(test_params)

    def scan(self, target, starttls=None):
        """Initiate scanning process (active)."""
        for scan_method in (f for f in dir(self) if f.startswith("_scan_")):
            print(" Starting scan: %s" % (scan_method.replace("_scan_", "")))
            getattr(self, scan_method)(
                target, starttls=starttls, test_params=self.capabilities.test_params
            )

    def sniff(self, target=None, iface=None, timeout=3):
        """Initiate sniffing process (passive)."""

        def _process(pkt):
            match_ip = (
                pkt.haslayer(IP)
                and (pkt[IP].src == target[0] or pkt[IP].dst == target[0])
                if target
                else True
            )
            match_port = (
                pkt.haslayer(UDP)
                and (pkt[UDP].sport == target[1] or pkt[UDP].dport == target[1])
                if target and len(target) == 2
                else True
            )
            if match_ip and match_port:
                self.capabilities.insert(pkt, client=False)
                events = self.capabilities.get_events()  # misuse get_events :/
                if events:
                    strconn = {"src": None, "dst": None, "sport": None, "dport": None}

                    if pkt.haslayer(IP):
                        strconn["src"] = pkt[IP].src
                        strconn["dst"] = pkt[IP].dst
                    if pkt.haslayer(UDP):
                        strconn["sport"] = pkt[UDP].sport
                        strconn["dport"] = pkt[UDP].dport

                    print(
                        "Connection: %(src)s:%(sport)d <==> %(dst)s:%(dport)d" % strconn
                    )
                    print("* EVENT - " + "\n* EVENT - ".join(e[0] for e in events))

        if iface:
            print("Choosen interface = {} ".format(iface))
        #     conf.iface = iface
        while True:
            bpf = None
            if target:
                bpf = "host %s" % target[0]
                if len(target) == 2:
                    bpf += " and udp port %d" % target[1]
            sniff(filter=bpf, prn=_process, store=0, timeout=timeout)

    def _scan_compressions(
        self, target, starttls=None, compression_list=None, test_params=None
    ):
        """Identify possible compressions in DTLS."""
        if not compression_list:
            compression_list = list(DTLS_COMPRESSION_METHODS.keys())
        for comp in compression_list:
            # prepare pkt
            pkt = DTLSRecord(
                sequence=0, content_type=TLSContentType.HANDSHAKE
            ) / DTLSHandshakes(
                handshakes=[
                    DTLSHandshake(fragment_offset=0)
                    / DTLSClientHello(
                        version=ENUM_DTLS_VERSIONS.DTLS_1_1,
                        cipher_suites=list(range(0xFE))[::-1],
                        compression_methods=comp,
                    )
                ]
            )
            try:
                client = DTLSClient(target, starttls=starttls, test_params=test_params)
                pkt[DTLSClientHello].cookie = client.cookie
                pkt[DTLSClientHello].cookie_length = client.cookie_length
                sent_time = test_params.report_sent_packet()
                client.sendall(pkt)
                resp = client.recvall(timeout=0.5)
                test_params.report_received_packet(sent_time)
                self.capabilities.insert(resp, client=False)
            except socket.error as sock_err:
                print(repr(sock_err))

    def xxx_scan_certificates(self, target, starttls=None, test_params=None):
        """Identify server certificates in DTLS."""
        # with open("512b-dsa-example-cert.der", "r") as file_handle:
        #     test_packet = file_handle.read().strip()
        # print("_scan_certificates")
        pkt_hello = DTLSRecord(
            sequence=0,
            content_type=TLSContentType.HANDSHAKE,
            version=ENUM_DTLS_VERSIONS.DTLS_1_1,
        ) / DTLSHandshakes(
            handshakes=[
                DTLSHandshake(fragment_offset=0)
                / DTLSClientHello(
                    version=ENUM_DTLS_VERSIONS.DTLS_1_1,
                    cipher_suites=list(range(0xFE))[::-1],
                    compression_methods=0,
                )
            ]
        )
        pkt = DTLSRecord(
            sequence=0,
            content_type=TLSContentType.HANDSHAKE,
            version=ENUM_DTLS_VERSIONS.DTLS_1_1,
        ) / DTLSHandshakes(
            handshakes=[
                DTLSHandshake(fragment_offset=0)
                / TLSCertificateList()
                / TLS13Certificate(
                    # certificates=[TLSCertificate(data=X509_Cert(test_packet))],
                    length=600
                )
            ]
        )
        print(pkt)
        try:
            client = DTLSClient(target, starttls=starttls, test_params=test_params)
            pkt_hello[DTLSClientHello].cookie = client.cookie
            pkt_hello[DTLSClientHello].cookie_length = client.cookie_length
            sent_time = test_params.report_sent_packet()
            client.sendall(pkt_hello)
            resp1 = client.recvall(timeout=0.1)
            test_params.report_received_packet(sent_time)
            self.capabilities.insert(resp1, client=False)
            sent_time = test_params.report_sent_packet()
            client.sendall(pkt)
            resp2 = client.recvall(timeout=0.5)
            test_params.report_received_packet(sent_time)
            self.capabilities.insert(resp2, client=False)
        except socket.error as sock_err:
            print(repr(sock_err))

    @staticmethod
    def _check_cipher(
        target,
        cipher_id,
        starttls=None,
        version=ENUM_DTLS_VERSIONS.DTLS_1_0,
        test_params=None,
    ):
        """Check whether particular cipher is listed."""
        pkt = DTLSRecord(
            sequence=0, content_type=TLSContentType.HANDSHAKE, version=version
        ) / DTLSHandshakes(
            handshakes=[
                DTLSHandshake(fragment_offset=0)
                / DTLSClientHello(
                    version=version, cipher_suites=[cipher_id], compression_methods=0
                )
            ]
        )
        try:
            client = DTLSClient(target, starttls=starttls, test_params=test_params)
            pkt[DTLSClientHello].cookie = client.cookie
            pkt[DTLSClientHello].cookie_length = client.cookie_length
            sent_time = test_params.report_sent_packet()
            client.sendall(pkt)
            resp = client.recvall(timeout=0.5)
            test_params.report_received_packet(sent_time)
        except socket.error as sock_err:
            print(repr(sock_err))
            return None
        return resp

    def scan_accepted_ciphersuites(
        self,
        target,
        starttls=None,
        cipherlist=None,
        version=ENUM_DTLS_VERSIONS.DTLS_1_0,
        test_params=None,
    ):
        """Identify possible ciphersuites of DTLS server."""
        if not cipherlist:
            cipherlist = list(DTLS_CIPHER_SUITES.keys())
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.workers
        ) as executor:
            tasks = [
                executor.submit(
                    self._check_cipher,
                    target,
                    cipher_id,
                    starttls,
                    version,
                    test_params,
                )
                for cipher_id in cipherlist
            ]
            for future in concurrent.futures.as_completed(tasks):
                self.capabilities.insert(future.result(), client=False)

    def _scan_supported_protocol_versions(
        self,
        target,
        starttls=None,
        versionlist=((k, v) for k, v in DTLS_VERSIONS.items() if v.startswith("DTLS_")),
        test_params=None,
    ):
        """Identify possible protocol versions of DTLS server."""
        for magic, ___ in versionlist:
            pkt = DTLSRecord(
                version=magic, sequence=0, content_type=TLSContentType.HANDSHAKE
            ) / DTLSHandshakes(
                handshakes=[
                    DTLSHandshake(fragment_offset=0)
                    / DTLSClientHello(
                        version=magic,
                        compression_methods=0,
                        cipher_suites=list(range(0xFE))[::-1],
                    )
                ]
            )  # ,
            # extensions=[TLSExtension() /
            #             TLSExtHeartbeat(mode=TLSHeartbeatMode.PEER_ALLOWED_TO_SEND)])])
            # pkt.show()
            try:
                client = DTLSClient(target, starttls=starttls, test_params=test_params)
                sent_time = test_params.report_sent_packet()
                client.sendall(pkt)
                resp = client.recvall(timeout=0.5)
                test_params.report_received_packet(sent_time)
                self.capabilities.insert(resp, client=False)
                resp = client.recvall(timeout=0.5)
                self.capabilities.insert(resp, client=False)
            except socket.error as sock_err:
                print(repr(sock_err))

    def _scan_scsv(self, target, starttls=None, test_params=None):
        """Verify SCSV support by DTLS server."""
        pkt = DTLSRecord(version=ENUM_DTLS_VERSIONS.DTLS_1_1) / DTLSHandshakes(
            handshakes=[
                DTLSHandshake()
                / DTLSClientHello(
                    version=ENUM_DTLS_VERSIONS.DTLS_1_0,
                    cipher_suites=[TLSCipherSuite.FALLBACK_SCSV]
                    + list(range(0xFE))[::-1],
                )
            ]
        )
        try:
            client = DTLSClient(target, starttls=starttls, test_params=test_params)
            sent_time = test_params.report_sent_packet()
            client.sendall(pkt)
            resp = client.recvall(timeout=2)
            test_params.report_received_packet(sent_time)
            self.capabilities.insert(resp, client=False)
            if not (
                resp.haslayer(TLSAlert)
                and resp[TLSAlert].description
                == TLSAlertDescription.INAPPROPRIATE_FALLBACK
            ):
                self.capabilities.report_issue(
                    "DOWNGRADE / POODLE - FALLBACK_SCSV - not honored", resp
                )
        except socket.error as sock_err:
            print(repr(sock_err))

    def xxx_scan_heartbleed(
        self,
        target,
        starttls=None,
        version=ENUM_DTLS_VERSIONS.DTLS_1_0,
        test_params=None,
    ):
        """Plugin for verifying vulnerability to Heartbleed attack by DTLS server."""
        try:
            client = DTLSClient(target, starttls=starttls, test_params=test_params)
            pkt = DTLSRecord(version=version) / DTLSHandshakes(
                handshakes=[DTLSHandshake() / DTLSClientHello(version=version)]
            )
            sent_time = self.test_params.report_sent_packet()
            client.sendall(pkt)
            resp1 = client.recvall(timeout=0.5)
            self.test_params.report_received_packet(sent_time)
            pkt = DTLSRecord(version=version) / TLSHeartBeat(
                length=2 ** 14 - 1, data="bleed..."
            )
            sent_time = self.test_params.report_sent_packet()
            client.sendall(str(pkt))
            resp2 = client.recvall(timeout=0.5)
            self.test_params.report_received_packet(sent_time)
            if resp2.haslayer(TLSHeartBeat) and resp2[TLSHeartBeat].length > 8:
                self.report_issue("HEARTBLEED - vulnerable", resp2)
        except socket.error as sock_err:
            print(repr(sock_err))
            return None
        return resp2

    def xxx_scan_secure_renegotiation(
        self,
        target,
        starttls=None,
        version=ENUM_DTLS_VERSIONS.DTLS_1_0,
        test_params=None,
    ):
        """Plugin for verifying vulnerability to Insecure Renegotiations by DTLS server."""
        # todo: also test EMPTY_RENEGOTIATION_INFO_SCSV
        try:
            client = DTLSClient(target, starttls=starttls, test_params=test_params)
            pkt = DTLSRecord(version=version) / DTLSHandshakes(
                handshakes=[
                    DTLSHandshake()
                    / DTLSClientHello(
                        version=version,
                        extensions=TLSExtension() / TLSExtRenegotiationInfo(),
                    )
                ]
            )
            sent_time = self.test_params.report_sent_packet()
            client.sendall(pkt)
            resp = client.recvall(timeout=0.5)
            self.test_params.report_received_packet(sent_time)
            if resp.haslayer(TLSExtRenegotiationInfo):
                self.report_issue(
                    "DTLS EXTENSION SECURE RENEGOTIATION - not supported", resp
                )
        except socket.error as sock_err:
            print(repr(sock_err))
            return None
        return resp


def active_scanning(test_params, test_cases):
    """Perform active scanning based on provided test params."""
    alive_before = service_ping(test_params)
    if not alive_before and not test_params.ignore_ping_check:
        print(
            "[+] Server {}:{} is not responding before starting scan - skipping this host!"
            "\n    (use --ignore-ping-check if you want to continue anyway)".format(
                test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
            )
        )
        return
    scanner = DTLSScanner(test_params)
    scanner.scan((test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port))
    print_verbose(test_params, scanner.capabilities)
    print(
        "\nHost: {}:{}".format(
            test_params.dst_endpoint.ip_addr, test_params.dst_endpoint.port
        )
    )
    print(
        "\n[*] Supported ciphers: %s/%s"
        % (len(scanner.capabilities.info.server.ciphers), len(DTLS_CIPHER_SUITES))
    )
    print(
        " * "
        + "\n * ".join(
            (
                "%s (0x%0.4x)"
                % (
                    DTLS_CIPHER_SUITES.get(
                        c, "SSLv2_%s" % SSLv2_CIPHER_SUITES.get(c, c)
                    ),
                    c,
                )
                for c in scanner.capabilities.info.server.ciphers
            )
        )
    )
    print(
        "\n[*] Supported protocol versions: %s/%s"
        % (len(scanner.capabilities.info.server.versions), len(DTLS_VERSIONS))
    )
    print(
        " * "
        + "\n * ".join(
            (
                "%s (0x%0.4x)" % (DTLS_VERSIONS.get(c, c), c)
                for c in scanner.capabilities.info.server.versions
            )
        )
    )
    print(
        "\n[*] Supported compressions methods: %s/%s"
        % (
            len(scanner.capabilities.info.server.compressions),
            len(DTLS_COMPRESSION_METHODS),
        )
    )
    print(
        " * "
        + "\n * ".join(
            (
                "%s (0x%0.4x)" % (DTLS_COMPRESSION_METHODS.get(c, c), c)
                for c in scanner.capabilities.info.server.compressions
            )
        )
    )
    events = scanner.capabilities.get_events()
    print(
        "\n[*] Server certificates: %s \n * (to see details use verbose mode)"
        % (len(scanner.capabilities.info.server.certificates))
    )
    print("\n[*] Events: %s" % len(events))
    print("* EVENT - " + "\n* EVENT - ".join(e[0] for e in events))


def main(args):
    """Start security active scanning based on command line parameters."""
    tester = CotopaxiTester(
        test_name="active scanning",
        check_ignore_ping=True,
        show_disclaimer=False,
        use_generic_proto=False,
    )
    tester.test_params.positive_result_name = "Identified issues"
    tester.test_params.potential_result_name = "Unidentified endpoints"
    tester.parse_args(args)
    tester.perform_testing("active security scanning", active_scanning)


if __name__ == "__main__":
    main(sys.argv[1:])
