# -*- coding: UTF-8 -*-
'''
@since: 21.11.2012
@author: nuabaranda@web.de
'''


import os.path
import logging

import pytest
from scapy.all import *
from scapy.layers.inet import IP, UDP
# from netaddr.ip import IPNetwork, IPAddress

from bacnet import BvlcFunction, BVLC, BACNET_PORT, NPDU, NetworkLayerMessageType, \
    hexStringToIntList, APDU, PduType, UnconfirmedServiceChoice


SRC_IP = '192.168.87.1'
DST_IP = '192.168.87.2'
DST_BROADCAST = '192.168.87.255'
DST_CIDR = '24'

PCAP_PATH = os.path.normpath("")

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()


pytestmark = pytest.mark.usefixtures('set_iface')


@pytest.fixture
def set_iface():
    show_interfaces()
#     print ifaces()
    print conf.iface
    # @todo: use netaddr to set suitable network interface
    conf.iface = "eth0"


@pytest.fixture
def udp():
    udp = IP(src=SRC_IP, dst=DST_IP) / UDP(sport=BACNET_PORT, dport=BACNET_PORT)
    return udp


@pytest.fixture
def npdu_global_broadcast(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b00100000,
                       dlen=0, dnet=0xFFFF,
                       hop_count=255)
    return npdu


@pytest.fixture
def npdu_distribute_broadcast(udp):
    bvlc = udp / BVLC(function=BvlcFunction.DISTRIBUTE_BROADCAST_TO_NETWORK)
    npdu = bvlc / NPDU(nlpci=0b00000000)
    return npdu


@pytest.mark.usefixtures('bind_bvlc')
def test_bvlc_read_bdt(udp):
    bvlc = udp / BVLC(function=BvlcFunction.READ_BDT)
    bvlc.show2()
    send(bvlc)
    log.debug(bvlc)

    bvlc = bvlc.__class__(str(bvlc))
    assert bvlc.length == 4


@pytest.mark.usefixtures('bind_bvlc')
def test_bvlc_register_fd(udp):
    bvlc = udp / BVLC(function=BvlcFunction.REGISTER_FD, time_to_live=60)
    bvlc.show2()
    send(bvlc)

    bvlc = bvlc.__class__(str(bvlc))
    assert bvlc.length == 6


@pytest.mark.usefixtures('bind_npdu')
def test_npdu_who_is_router_to_network_no_net(udp):
    bvlc = BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    pkt = udp / bvlc
    npdu = NPDU(nlpci=0b10000000,
                message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK)
    pkt = pkt / npdu
    pkt.show2()
    send(pkt)

    pkt = pkt.__class__(str(pkt))
    assert pkt['BVLC'].length == 7
    assert pkt['NPDU'].network == None



@pytest.mark.usefixtures('bind_npdu')
def test_npdu_who_is_router_to_network_with_net(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10000000,
                       message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                       network=1)
    npdu.show2()
    send(npdu)

    npdu = npdu.__class__(str(npdu))
    assert npdu['BVLC'].length == 9
    assert npdu['NPDU'].network == 1


@pytest.mark.usefixtures('bind_npdu')
def test_npdu_who_is_router_to_network_no_net_with_dest(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10100000,
                       message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                       dadr=hexStringToIntList('01'), dnet=99,
                       hop_count=255)
    npdu.show2()
    send(npdu)

    npdu = npdu.__class__(str(npdu))
    assert npdu['BVLC'].length == 12
    assert npdu['NPDU'].network == None


@pytest.mark.usefixtures('bind_npdu')
def test_npdu_who_is_router_to_network_with_net_with_dest(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10100000,
                       message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                       dadr=hexStringToIntList('01'), dnet=99,
                       hop_count=255,
                       network=2)
    npdu.show2()
    send(npdu)

    npdu = npdu.__class__(str(npdu))
    assert npdu['BVLC'].length == 14
    assert npdu['NPDU'].network == 2


@pytest.mark.usefixtures('bind_npdu')
def test_npdu_who_is_router_to_network_with_net_with_source(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10001000,
                       message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                       sadr=hexStringToIntList('FFFF'), snet=80,
                       network=3)
    npdu.show2()
    send(npdu)

    npdu = npdu.__class__(str(npdu))
    assert npdu['BVLC'].length == 14
    assert npdu['NPDU'].network == 3


@pytest.mark.usefixtures('bind_npdu')
def test_npdu_who_is_router_to_network_with_net_with_dest_with_source(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10101000,
                       message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                       dadr=hexStringToIntList('01'), dnet=99,
                       sadr=hexStringToIntList('FFFF'), snet=80,
                       hop_count=255,
                       network=4)
    npdu.show2()
    send(npdu)

    npdu = npdu.__class__(str(npdu))
    assert npdu['BVLC'].length == 19
    assert npdu['NPDU'].network == 4


@pytest.mark.usefixtures('bind_npdu')
def test_npdu_i_am_router_to_network(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10000000,
                       message_type=NetworkLayerMessageType.I_AM_ROUTER_TO_NETWORK,
                       networks=[1, 2, 3])
    npdu.show2()
    send(npdu)

    npdu = npdu.__class__(str(npdu))
    assert npdu['BVLC'].length == 13
    assert npdu['NPDU']


@pytest.mark.usefixtures('bind_npdu')
def test_npdu_i_am_router_to_network_global_broadcast(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10100000,
                       dlen=0, dnet=0xFFFF,
                       hop_count=255,
                       message_type=NetworkLayerMessageType.I_AM_ROUTER_TO_NETWORK,
                       networks=[1, 2, 3])
    npdu.show2()
    send(npdu)

    npdu = npdu.__class__(str(npdu))
    assert npdu['BVLC'].length == 17
    assert npdu['NPDU']


@pytest.mark.usefixtures('bind_apdu')
def test_apdu_who_is_global_broadcast(npdu_global_broadcast):
    apdu = npdu_global_broadcast / APDU(pdu_type=PduType.UNCONFIRMED_REQUEST,
                                        service_choice=UnconfirmedServiceChoice.WHO_IS)
    apdu.show2()
    send(apdu)

    apdu = apdu.__class__(str(apdu))
    assert apdu['BVLC'].length == 12
    assert apdu['APDU']


@pytest.mark.usefixtures('bind_apdu')
def test_apdu_who_is_distribute_broadcast(npdu_distribute_broadcast):
    apdu = npdu_distribute_broadcast / APDU(pdu_type=PduType.UNCONFIRMED_REQUEST,
                                            service_choice=UnconfirmedServiceChoice.WHO_IS)
    apdu.show2()
    send(apdu)

    apdu = apdu.__class__(str(apdu))
    assert apdu['BVLC'].length == 8
    assert apdu['APDU']


#    def whoIsRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, net=None):
#        p = self.getWhoIsRouterToNetwork(ipDest, dest, source, hopCount, net)
#        ans, unans = sr(p, multi=True, timeout=3, verbose=3)
#        for answer in ans:
#            answer.summarize()


#    def _testSendIAmRouterToNetworkIPBroadcast(self):
#        self.fakeBacDev.sendIAmRouterToNetwork(IPNetwork('/'.join([DST_BROADCAST, DST_CIDR])),
#                                                         dest={'dnet' : 99, 'dadr' : '01'},
#                                                         nets=[8,9])
#
#    def _testSendWhoIsRouterToNetworkIPUnicast(self):
#        self.fakeBacDev.sendWhoIsRouterToNetwork(IPAddress(DST_IP),
#                                                 dest={'dnet' : 99, 'dadr' : '01'}, net=78)
#
#    def _testSendWhoIsRouterToNetworkIPBroadcast(self):
#        self.fakeBacDev.sendWhoIsRouterToNetwork(IPNetwork('/'.join([DST_BROADCAST, DST_CIDR])),
#                                                           dest={'dnet' : 99, 'dadr' : '01'},
#                                                           net=78)
#
#    def _testSendWhoIsRouterToNetworkDestBroadcast(self):
#        self.fakeBacDev.sendWhoIsRouterToNetwork(IPNetwork('/'.join([DST_BROADCAST, DST_CIDR])),
#                                                 dest={'dnet' : 99, 'dlen' : 0}, net=78)
#
#    def _testWhoIsRouterToNetwork(self):
#        self.fakeBacDev.whoIsRouterToNetwork(IPNetwork('/'.join([DST_BROADCAST, DST_CIDR])))


