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
    NPDUSource, NPDUDest, hexStringToIntList, APDU, PduType, UnconfirmedServiceChoice


SRC_IP = '192.168.87.1'
DST_IP = '192.168.87.2'
DST_BROADCAST = '192.168.87.255'
DST_CIDR = '24'

PCAP_PATH = os.path.normpath("")

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()


@pytest.fixture
def udp():
    udp = IP(src=SRC_IP, dst=DST_IP) / UDP(sport=BACNET_PORT, dport=BACNET_PORT)
    return udp


@pytest.fixture
def npdu_global_broadcast(udp):
    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b00100000,
                     dest=NPDUDest(dlen=0, dnet=0xFFFF),
                     hop_count=255)
    return npdu


@pytest.fixture
def npdu_distribute_broadcast(udp):
    bvlc = udp / BVLC(function=BvlcFunction.DISTRIBUTE_BROADCAST_TO_NETWORK)
    npdu = bvlc / NPDU(nlpci=0b00000000)
    return npdu


def test_ifaces():
    show_interfaces()
#     print ifaces()
    print conf.iface
    conf.iface = "eth0"
    assert False


@pytest.mark.usefixtures('bind_bvlc')
def test_bvlc_read_bdt(udp):
    bvlc = udp / BVLC(function=BvlcFunction.READ_BDT)
    bvlc.show2()
    send(bvlc)
    log.debug(bvlc)
    assert bvlc.length == 4


@pytest.mark.usefixtures('bind_bvlc')
def test_bvlc_register_fd(udp):
    bvlc = udp / BVLC(function=BvlcFunction.REGISTER_FD, time_to_live=60)
    bvlc.show2()
    send(bvlc)
    assert bvlc.length == 6


@pytest.mark.usefixtures('bind_bvlc')
def test_npdu_who_is_router_to_network_no_net(udp):
    bind_layers(BVLC, NPDU, function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)

    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10000000,
                     message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK)
    npdu.show2()
    send(npdu)
    print npdu['BVLC'].length
    assert npdu['BVLC'].length == 7


@pytest.mark.usefixtures('bind_bvlc')
def test_npdu_who_is_router_to_network_with_net(udp):
    bind_layers(BVLC, NPDU, function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)

    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10000000,
                       message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                       network=1)
    npdu.show2()
    send(npdu)
    print npdu['BVLC'].length
    assert npdu['BVLC'].length == 9


@pytest.mark.usefixtures('bind_bvlc')
def test_npdu_who_is_router_to_network_with_dest(udp):
    bind_layers(BVLC, NPDU, function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)

    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10100000,
                     message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                     dest=NPDUDest(dadr=hexStringToIntList('01'), dnet=99),
                     hop_count=255,
                     network=2)
    npdu.show2()
    send(npdu)
    print npdu['BVLC'].length
    assert npdu['BVLC'].length == 14


@pytest.mark.usefixtures('bind_bvlc')
def test_npdu_who_is_router_to_network_with_source(udp):
    bind_layers(BVLC, NPDU, function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)

    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10001000,
                     message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                     source=NPDUSource(sadr=hexStringToIntList('FFFF'), snet=80),
                     network=3)
    npdu.show2()
    send(npdu)
    assert npdu['BVLC'].length == 14


@pytest.mark.usefixtures('bind_bvlc')
def test_npdu_who_is_router_to_network_with_dest_and_source(udp):
    bind_layers(BVLC, NPDU, function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)

    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10101000,
                     message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                     dest=NPDUDest(dadr=hexStringToIntList('01'), dnet=99),
                     source=NPDUSource(sadr=hexStringToIntList('FFFF'), snet=80),
                     hop_count=255,
                     network=4)
    npdu.show2()
    send(npdu)
    assert npdu['BVLC'].length == 19


@pytest.mark.usefixtures('bind_bvlc')
def test_npdu_i_am_router_to_network(udp):
    bind_layers(BVLC, NPDU)

    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10000000,
                     message_type=NetworkLayerMessageType.I_AM_ROUTER_TO_NETWORK,
                     networks=[1, 2, 3])
    npdu.show2()
    send(npdu)


@pytest.mark.usefixtures('bind_bvlc')
def test_npdu_i_am_router_to_network_global_broadcast(udp):
    bind_layers(BVLC, NPDU)

    bvlc = udp / BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc / NPDU(nlpci=0b10100000,
                     dest=NPDUDest(dlen=0, dnet=0xFFFF),
                     hop_count=255,
                     message_type=NetworkLayerMessageType.I_AM_ROUTER_TO_NETWORK,
                     networks=[1, 2, 3])
    npdu.show2()
    send(npdu)


@pytest.mark.usefixtures('bind_apdu')
def test_apdu_who_is_global_broadcast(npdu_global_broadcast):
    apdu = npdu_global_broadcast / APDU(pdu_type=PduType.UNCONFIRMED_REQUEST,
                                      service_choice=UnconfirmedServiceChoice.WHO_IS)
    apdu.show2()
    send(apdu)


@pytest.mark.usefixtures('bind_apdu')
def test_apdu_who_is_distribute_broadcast(npdu_distribute_broadcast):
    apdu = npdu_distribute_broadcast / APDU(pdu_type=PduType.UNCONFIRMED_REQUEST,
                                          service_choice=UnconfirmedServiceChoice.WHO_IS)
    apdu.show2()
    send(apdu)


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


