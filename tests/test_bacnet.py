# -*- coding: UTF-8 -*-
'''
@since: 21.11.2012
@author: nuabaranda@web.de
'''

__version__ = ""
# $Source$


import unittest
import os.path

from netaddr.ip import IPNetwork, IPAddress

from itf.btf.dev_stub import BacDevStub, readPCAP
from tests.init_tests import TEST_DATA

SRC_IP = '192.168.88.1'
DST_IP = '168.152.32.39'
DST_BROADCAST = '168.152.32.255'
DST_CIDR = '24'
PORT = 47808

PCAP_PATH = os.path.normpath("")


class TestBacDevStub(unittest.TestCase):
    
    def setUp(self):
        self.fakeBacDev = BacDevStub(SRC_IP, PORT, verb=3)

    def _testRegFd(self):
        self.fakeBacDev.sendBvlcRegFd(DST_IP, ttl=300)

    def _testSendNpdu(self):
        self.fakeBacDev.sendNpdu(DST_IP)
        
    def _testSendIAmRouterToNetworkIPBroadcast(self):
        self.fakeBacDev.sendIAmRouterToNetwork(IPNetwork('/'.join([DST_BROADCAST, DST_CIDR])), 
                                                         dest={'dnet' : 99, 'dadr' : '01'}, 
                                                         nets=[8,9])

    def _testSendWhoIsRouterToNetworkIPUnicast(self):
        self.fakeBacDev.sendWhoIsRouterToNetwork(IPAddress(DST_IP), 
                                                 dest={'dnet' : 99, 'dadr' : '01'}, net=78)

    def _testSendWhoIsRouterToNetworkIPBroadcast(self):
        self.fakeBacDev.sendWhoIsRouterToNetwork(IPNetwork('/'.join([DST_BROADCAST, DST_CIDR])), 
                                                           dest={'dnet' : 99, 'dadr' : '01'}, 
                                                           net=78)

    def _testSendWhoIsRouterToNetworkDestBroadcast(self):
        self.fakeBacDev.sendWhoIsRouterToNetwork(IPNetwork('/'.join([DST_BROADCAST, DST_CIDR])), 
                                                 dest={'dnet' : 99, 'dlen' : 0}, net=78)    

    def _testWhoIsRouterToNetwork(self):
        self.fakeBacDev.whoIsRouterToNetwork(IPNetwork('/'.join([DST_BROADCAST, DST_CIDR])))
        
    def testReadPCAP(self):
        readPCAP(os.path.join(TEST_DATA, 'pcap', 'who_is_router_to_network.pcap'))

def suite():
    tests = []
    testLoader = unittest.TestLoader()
    for testCase in [
                     TestBacDevStub
                              ]:
        tests.extend(testLoader.loadTestsFromTestCase(testCase))
    return unittest.TestSuite(tests)


if __name__ == "__main__": 
    unittest.main()
#    unittest.TextTestRunner(verbosity=2).run(suite())