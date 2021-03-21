# -*- coding: utf-8 -*-
"""Protocol tester for QUIC protocol."""
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
from scapy.all import ICMP, UDP

from .protocol_tester import UDPBasedProtocolTester
from .common_utils import udp_sr1, print_verbose

QUIC_PING_000 = (
    "c6ff000018080979593d315c3e42000044ee28e4e6a46ee9d58405b93a042b6d3f4f944e"
    "d91af7cd27f54ff37422130c6f61b08caf84ea7f356c09d1e8e0c33b65a058866b80edb5"
    "df3789ef955905dc6324e8f1474ed223adc135acba1f96596c90987bb9875b2f2d397437"
    "e794726108ab6a7afbcc35f69d4fa615e202f6e48c733ff28a6783b276d862e760d7a72c"
    "2cb5bcf6defc440395d859ffa3fd8794be5d8b123558729c9e3f686922cef5725ef29473"
    "28894c564703d74090f96e21329673011c08dc9b93bc8376db8f1e7d50cca87eaa0e6359"
    "0bf6e3af2dfb8a1065319764fc51078133a515a61ec7aed7200e51acf95bab178550f498"
    "97e290f2b51e6a08d0b294552fc2d4a1ab1d05ef46e31a50ee12b293ee34d604d23f1f5a"
    "dc289c0ceae1c8f4135b06ce277c27f4f2778b1f26eb3b2c8c5b439ac2b947b519e7f86d"
    "1426faac85dfb1c931cf14fa924d71ca407bc4172e9b4e2b36a59268a8020a5ed1828b56"
    "3e1d5d595668cff2bf492663eb5bc6216f5daac64cd873fe781946bc9ed37b7b721c67e5"
    "91aad1c12da9d2814379ebe0605a6a239ac2bf8899137bc5118f8aedcc063099f7ee5058"
    "2082c29dd93bac0d9d5765c13c868ea48e173bafbabef3e86586fb3f9807c7208eb9b502"
    "e124b862e03040c1ef5a07abd4ecfeea101407f95b3ad4da97f86fd41aad3d03bb3a0c27"
    "f6bdd85f538d8590604b1abbb786353f4295533a66b22348ccda16cc93a4513a72092d7e"
    "0fa785c295367677ef4726a5b6280d6d2f2f4fe30edbe2f3fa90838f25353929f0f0454c"
    "02f90fe8248bbf890b7c9927bae0c19b6c95a41ffc5f1f31525c8578f614a9e89d081960"
    "2d58e38b25f59fcc356b21314616bc94c4bbaece4ab60de8402d2f66eb08396987a3f30c"
    "6cdfcafa03240e684bbd5ff83a7a5c667dd9adbeb673f72e40e0b9aa103a39b1355bf4b8"
    "e2dfb2d80d60c27ebce3f1ea916dc0c3ca446c4a730c5c075f1e6e164a93b30791335948"
    "6ead8c8fbe219d872f91f8769283f58dd47ed9eb12324d10d2fc8f2c1674426d118ec646"
    "149d167e897f03216dfe33d37c4a0c551179a66b3e3bbd6638c39f39f443361c80b80b4e"
    "066f73398ca0f81452db8fa86f6c1e83291699bd6ac4b719d33ac948a112eb46ec5a8527"
    "9c97dd6f4022a350875cdb51e0ad5403ab52d762679ffb9f1e4e9727ae9dcb7441e9a30a"
    "f3e454a381e8e89f756e224194f34a52113102a0928f318938525d9d348058ba99152015"
    "bdaa29787da204025a1b232565a9761f849d5cc29992b7ce3f575852a8e2f14a6af814d7"
    "db10c99accc1b01cc63190875962e9190d5264311e6b67425543da7be1a963d24c117e93"
    "ce4210c954ab6ee39286b9a5fe3ef72451f71a0edd391b354811fa978b987f463ab34c0b"
    "04fb0c119cd14848d18d6e75d7749db99cc429e272ab960103991bc5bb6cc935e4db493a"
    "61286edd8bc057ac7512ad41954b23f4cb7e204e5403903c0dbc9b1d037040fce6cc9f4e"
    "50ad685c20194fbc6090bb149d18a06865bfe50b823da200c4751570f8b918a56ad1d9b3"
    "445505ac0e087a3677f5abd79c8430b8710b2a176880a94409a58f6127e934d6e80b76aa"
    "951529c8c7bea7c6d34a1bf6be5b55396116a23da15d9df81b09d11a5bfe1c2c88e3090e"
    "dd10cee838519867ae803e295c2b81b7cbcaa4e94c0dfe2798a095f1b5ecbd019df2aec2"
    "7eb0ac55d7002709f8db9e1931893ed1775712f80c8e4aa1214593e0109f1d3aede5da4f"
    "38e34e18cc49de9a924a077f98a7c38d5b40691d"
)

QUIC_PING_001 = (
    "c2ff00001708f6fd33631d1c5e9e08a2a07012ac95254e0044caf75c8c168d169c3d985f"
    "9baa4c596511f5b7739da7974d6516f6d8d1c76cb742c7a30ba459c68b835ebdb73e4cd4"
    "1afb666c3018032333d35dbddd8c3a49e31ed9c3829252a00297e436fa431df62dbbb781"
    "e5adcf26a6532e1c2a1b50c788bf6bdbe8ce191e853fbb2ae77b1f002cb9c363823db1e1"
    "cff35367196125b323903c21d84410a3db43394bc0d165387bcf87bb0dbf9c2f568185f0"
    "3d3ef710cbda293182663f015be19cb4c6aa9c6788591a03bf5ed8ce6fb28f7eafa7b5e4"
    "63b981d2134f73cadc603b7400f84e47036e7bdd88859226aaf75bfaac8a37cc62cbd9bf"
    "717bb8704305f225441871f681459017a6844fa4b5efe0f7e3ca89df1b266f0ccd804d76"
    "7191a14a78648a886d369b75f96021ca05f3aadde128c587d5770fa28fe21248327ba304"
    "08ee0ff086832ede0213f5eaea954d554495a4bc73b9db9f95012fc73dd83aaf8efab48f"
    "5cdee7a9bc43e2e61b1a06491bcc8a0d651014cb11f492b7c12e4d933219c98d2fe30afe"
    "7ac3ffd9345a55fc6cb8953d0b3f84e2d1db6f328dbc4f40889f89e1e0531c4fd9decd35"
    "dfd85bd4203692b41f94b1fe31b6fa3c382ea1109f5cdf124c2e88c0ecb49e86aa76c7e9"
    "3ca911a3ad9086e0eb1a2ba8c5e77001c9b4ac55bb9d61e10f86693913c134687b67a808"
    "fc480fe5391b45b8423dbdf487213edf6d0921f559e190bd804a9d8353c4037d0d004118"
    "e067faa6ae58b381c1f84593974ec00df6b127939a1f92050d1ebbea4a5809982eb87e8b"
    "870d9d7b6ab558381ec4e0d575cc0220520252e0c190d5fe48b268e5c377f2c0a44db38d"
    "1493dea2a6a44d7f0cb1570a9926e2368914f1ac115c889bddae1ee44d7738c403a7b764"
    "f85daa6c0c3f82a162c44b7bd64704c6abe9ccace600006d31fc85c66a4cf9f435beab37"
    "c78753b7bd8337d099de4989fe10fcea5ae6dae3d8fc472c88cd8dbdca7ed169c05fee70"
    "0dc878b7f51693891e7c8b75ea81d17986c04588892cd2ff438d7b6de89722c98f60b4fd"
    "6de0db9e06680c0af25544674ff107c27e24ef1cadab30f090df1f6037657045060b63dd"
    "88bbfdfdc2ee88abf450dbc6fab5f8b6f5ba8bd59fada770d2116142af8206e0dc28f155"
    "706ce436fbcbe6ffce2672b1f34843b9f8861fefb8b8286e94de3aa3aa11ecb26d3a078b"
    "86b3a958a2e6361b1e6a15dc601d090f1b9948eba1720db3a647887183437ce6bfdee174"
    "721bca78a9916b3c38a79fd2952f0712c15b171fe89df243d06b328f57619c4eac7e85f5"
    "e28d4eb9005a0abb68f3d2c7aa366d2cbc9db1f3cfae46bd4a70a30382a73680b3b7b677"
    "9737bd2533f8fd0c5f872f12c8291f2ee757a289ed65e0c3f2131e5c38612e0731aa2304"
    "30cf0ada949dbcf6932ae3e8c04e261be124fcdc37f4f8fd937c0763f98c814d73bcc505"
    "82bc9c2a826935b0ceefab138f95041ce92e2ab6738897b9c08607583efde863057ab8e3"
    "f9b9a4cb1b38fb649ace5edfeaaac6b7b645b81e7ba4b007bf4c272e71e3e05136a16a35"
    "470d64d012603f372adfdab93597ce76482af0843ca70db832cc13c9f847c89c75f0645c"
    "ea74f7dd10b8ee58812ce6c889e88c7dcfd18f8b647cfd0fb72d364db5a6288952fbd6f9"
    "6cc7dea5febd861ab06affa6236f041b0dd6ce018e60b26f987ccec26529f7e44f9b5cf6"
    "f0fa52e2066af76a5f604e9aa259008401a9b536c87ead64f42d50b5"
)


class QUICTester(UDPBasedProtocolTester):
    """Tester of QUIC protocol."""

    def __init__(self):
        """Create empty QUICTester object."""
        UDPBasedProtocolTester.__init__(self)

    @staticmethod
    def protocol_short_name():
        """Provide short (abbreviated) name of protocol."""
        return "QUIC"

    @staticmethod
    def protocol_full_name():
        """Provide full (not abbreviated) name of protocol."""
        return "Quick UDP Internet Connections"

    @staticmethod
    def default_port():
        """Provide default port used by implemented protocol."""
        return 443

    @staticmethod
    def request_parser():
        """Provide Scapy class implementing parsing of protocol requests."""
        return UDP

    @staticmethod
    def response_parser():
        """Provide Scapy class implementing parsing of protocol responses."""
        return UDP

    @staticmethod
    def ping(test_params, show_result=False):
        """Check whether QUIC server is responding."""
        if not test_params:
            return None

        ping_packets = [QUIC_PING_000, QUIC_PING_001]
        for ping_packet in ping_packets:
            ping_data = codecs.decode(ping_packet, "hex")

            response = udp_sr1(test_params, ping_data)
            if not response:
                continue
            if ICMP in response and response[ICMP].type == 3:
                print_verbose(test_params, "Received ICMP dest-unreachable")
                continue
            if 50 < len(response) < 70 or 1000 < len(response) < 2000:
                return True
            else:
                print("Received unknown message len: {}".format(len(response)))
            # parsed_response = scrap_response(test_params, response)
            # if check_dtls_response(test_params, parsed_response):
            #     return True
        return False
