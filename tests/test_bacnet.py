# -*- coding: UTF-8 -*-
'''
@since: 21.11.2012
@author: nuabaranda@web.de
'''

__version__ = ""
# $Source$


import sys
import os.path

from scapy.all import *
from scapy.layers.inet import IP, UDP
from netaddr.ip import IPNetwork, IPAddress
import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from bacnet import BvlcFunction, BVLC, BVLCConditional, BVLCBase, BVLCReadBDT, BACNET_PORT, NPDU,\
    NetworkLayerMessageType


SRC_IP = '192.168.88.1'
DST_IP = '168.152.32.39'
DST_BROADCAST = '168.152.32.255'
DST_CIDR = '24'

PCAP_PATH = os.path.normpath("")


@pytest.fixture
def bind_bvlc():
    bind_layers(UDP, BVLC, sport=BACNET_PORT)
    bind_layers(UDP, BVLC, dport=BACNET_PORT)
    

@pytest.fixture
def udp():
    udp = IP(src=SRC_IP, dst=DST_IP)/UDP(sport=BACNET_PORT, dport=BACNET_PORT)
    return udp


@pytest.mark.usefixtures('bind_bvlc')
def test_bvlc_read_bdt(udp):
    bvlc = udp/BVLC(function=BvlcFunction.READ_BDT)
    bvlc.show2()
    send(bvlc)
    assert True == False


@pytest.mark.usefixtures('bind_bvlc')
def test_bvlc_register_fd(udp):
    bind_layers(BVLC, BVLCConditional)
    bvlc = udp/BVLC(function=BvlcFunction.REGISTER_FD)/BVLCConditional(time_to_live=60)
    bvlc.show2()
    send(bvlc)
    assert True == False


def test_send_bvlc_read_bdt(udp):
    bind_layers(UDP, BVLCBase, sport=BACNET_PORT)
    bind_layers(UDP, BVLCBase, dport=BACNET_PORT)
    
    bind_layers(BVLCBase, BVLCReadBDT, function=BvlcFunction.READ_BDT)
    
    p = udp/BVLCReadBDT()
    p.show()
    p.show2()
    send(p)
    assert True == False


@pytest.mark.usefixtures('bind_bvlc')
def test_npdu_who_is_router_to_network(udp):
#    bind_layers(BVLC, BVLCConditional)
    bind_layers(BVLC, NPDU)
    
    bvlc = udp/BVLC(function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    npdu = bvlc/NPDU(nlpci=0b10000000, message_type=NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK,
                     network=1)
#    npdu.show()
    npdu.show2()
    send(npdu)
    print npdu['BVLC'].length
    assert npdu['BVLC'].length == 9
    assert True == False


#class BacDevStub(object):
#    '''
#    Very simple stub for a BACnet device.
#    '''
#    
#    def __init__(self, srcIP=None, port=None, verb=0):
#        if srcIP is None or port is None:
#            tdIP, tdPort = BtfHelper.getTdIpAndPort()
#        self.srcIpAddr = tdIP if srcIP is None else srcIP
#        self.port = tdPort if port is None else port
#        
#        scapy_conf.verb=verb
##        scapy_conf.logLevel = 100
#        
#        bind_layers(UDP, BVLCBase, sport=port)
#        bind_layers(UDP, BVLCBase, dport=port)
#        
#        self.ip = IP()
#        self.ip.src = self.srcIpAddr
#        self.udp = self.ip/UDP(sport=port, dport=port)
#
#        
#    def sendBvlcReadBdt(self, destIp):
#        ip = IP()
#        ip.src = self.srcIpAddr
#        ip.dst = destIp
#        send(ip/UDP(sport=self.port, dport=self.port)/BVLCReadBDT)
#
#    def sendBvlcRegFd(self, destIp, ttl):
#        ip = IP()
#        ip.src = self.srcIpAddr
#        ip.dst = destIp
#        send(ip/UDP(sport=self.port, dport=self.port)/BVLCRegisterFD(time_to_live=ttl))
#        
#    
#    def sendNpdu(self, destIp):
#        ip = IP()
#        ip.src = self.srcIpAddr
#        ip.dst = destIp
#        send(ip/UDP(sport=self.port, dport=self.port)/BVLCOrigUnicastNPDU()/NPDUBase())
#
#    def getUDP(self, destIp):
#        ip = IP()
#        ip.src = self.srcIpAddr
#        ip.dst = destIp
#        return ip/UDP(sport=self.port, dport=self.port)
#    
#    def getBVLC(self, ipDest):
#        if isinstance(ipDest, IPNetwork):
#            udp = self.getUDP(str(ipDest.broadcast))
#            bvlc = udp/BVLCOrigBroadcastNPDU()
#        elif isinstance(ipDest, IPAddress):
#            udp = self.getUDP(str(ipDest))
#            bvlc = udp/BVLCOrigUnicastNPDU()
#        else:
#            raise ArgumentError('Invalid class for IP destination')
#        return bvlc
#    
#    def sendIAmRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, nets=None):
#        '''
#        @type ipDest: IPNetwork for broadcast or IPAddress for unicast
#        @param dest: NPDU destination
#        @type dest: Dict with dnet (int) and dadr (string with hex MAC)
#        @param source: NPDU source
#        @type source: Dict with snet and sadr (string with hex MAC)
#        '''
#        
#        content = NPDUIAmRouterToNetworkContent(npdu=getNPDUBase(dest, source, hopCount), 
#                                                networks=nets)
#        iAmRouterToNetwork = NPDU(content=content)
#        p = self.getBVLC(ipDest)/iAmRouterToNetwork
#        p.show2()
#        send(p)
#        
#    def getWhoIsRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, net=None):
#        content = NPDUWhoIsRouterToNetworkContent(npdu=getNPDUBase(dest, source, hopCount), 
#                                                  network=net)
#        whoIsRouterToNetwork = NPDU(content=content)
#        p = self.getBVLC(ipDest)/whoIsRouterToNetwork
#        return p
#        
#    def sendWhoIsRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, net=None):
#        p = self.getWhoIsRouterToNetwork(ipDest, dest, source, hopCount, net)
#        send(p)
#        
#    def whoIsRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, net=None):
#        p = self.getWhoIsRouterToNetwork(ipDest, dest, source, hopCount, net)
#        ans, unans = sr(p, multi=True, timeout=3, verbose=3)
#        for answer in ans:
#            answer.summarize()
#            
#
#def readPCAP(path, port=47808):
#    bind_layers(UDP, BVLCBase, sport=port)
#    bind_layers(UDP, BVLCBase, dport=port)
#    bind_layers(BVLCBase, NPDU,
#                function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
#    bind_layers(NPDU, NPDUContentBase)
#    bind_layers(NPDU, NPDUBase)
#    
#    packets = rdpcap(path)
#    packets.summary()
#    for packet in packets:
#        packet.summary()
#        npdu = packet['NPDU']
#        npdu.summary()

#class TestBacDevStub(unittest.TestCase):
#    
#    def setUp(self):
#        self.fakeBacDev = BacDevStub(SRC_IP, PORT, verb=3)
#
#    def _testRegFd(self):
#        self.fakeBacDev.sendBvlcRegFd(DST_IP, ttl=300)
#
#    def _testSendNpdu(self):
#        self.fakeBacDev.sendNpdu(DST_IP)
#        
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
#        
#    def testReadPCAP(self):
#        readPCAP(os.path.join(TEST_DATA, 'pcap', 'who_is_router_to_network.pcap'))

#def suite():
#    tests = []
#    testLoader = unittest.TestLoader()
#    for testCase in [
#                     TestBacDevStub
#                              ]:
#        tests.extend(testLoader.loadTestsFromTestCase(testCase))
#    return unittest.TestSuite(tests)
#
#
#if __name__ == "__main__": 
#    unittest.main()
##    unittest.TextTestRunner(verbosity=2).run(suite())