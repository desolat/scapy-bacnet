# -*- coding: UTF-8 -*-
'''
BACnet device stub to simulate some behavior.

Evolution steps:

1) Faked packets (e.g. fake remote device requests).
2) @todo: Fake device behavior (e.g. automatically answer requests).

@since: 21.11.2012
@author: nuabaranda@web.de
'''

__version__ = ""
# $Source$


import sys
import logging

from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.config import conf as scapy_conf

from itf.commons.commons import Enum
from netaddr.ip import IPAddress, IPNetwork
from itf.commons.exception import ArgumentError
from itf.btf.helper import BtfHelper

#logging.getLogger("scapy").setLevel(logging.DEBUG)
#log_runtime.setLevel(logging.DEBUG)
#log_interactive.setLevel(logging.DEBUG)
#log_loading.setLevel(logging.DEBUG)

log = logging.getLogger()


class StreamToLogger(object):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """

    def __init__(self, logger, log_level=logging.INFO):
        self.logger = logger
        self.log_level = log_level
        self.linebuf = ''
 
    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.log_level, line.rstrip())
 
stdout_logger = logging.getLogger('STDOUT')
sl = StreamToLogger(stdout_logger, logging.INFO)
sys.stdout = sl
 
stderr_logger = logging.getLogger('STDERR')
sl = StreamToLogger(stderr_logger, logging.ERROR)
sys.stderr = sl


class BvlcFunction(Enum):
    RESULT = 0
    WRITE_BDT = 1
    READ_BDT = 2
    READ_BDT_ACK = 3
    FORWARDED_NPDU = 4
    REGISTER_FD = 5
    ORIGINAL_UNICAST_NPDU = 10
    ORIGINAL_BROADCAST_NPDU = 11


class BVLCBase(Packet):
    name = 'BVLC-BASE'
    fields_desc = [XByteField('type', 0x81),
                   ByteEnumField('function', BvlcFunction.RESULT, BvlcFunction.revDict()),
                   ]

class BVLC(Packet):
    name = 'BVLC'
    fields_desc = [
                   PacketListField('bvlc_base',
                                   None, 
                                   BVLCBase),
                   ConditionalField(ShortField('time_to_live', None),
                                    lambda pkt: pkt.function == BvlcFunction.READ_BDT),
                   ConditionalField(IPField('origin_ip', None), 
                                    lambda pkt: pkt.function == BvlcFunction.FORWARDED_NPDU),
                   ConditionalField(ShortField('origin_port', 47808), 
                                    lambda pkt: pkt.function == BvlcFunction.FORWARDED_NPDU),
                   ]

class BVLCReadBDT(Packet):
    name = 'BVLC-READ-BDT'
    fields_desc = [
                   PacketListField('plist', 
                                   BVLCBase(function='READ_BDT'), 
                                   BVLCBase, 
                                   length_from = lambda pkt:pkt.length),
                   FieldLenField('length', None, length_of='plist', adjust = lambda pkt,x:x+2)
                   ]


class BVLCRegisterFD(Packet):
    name = 'BVLC-REGISTER-FD'
    fields_desc = [
                   PacketListField('plist', 
                                   BVLCBase(function='REGISTER_FD'), 
                                   BVLCBase, 
                                   length_from = lambda pkt:pkt.length),
                   FieldLenField('length', None, length_of='plist', adjust = lambda pkt,x:x+4),
                   ShortField('time_to_live', None)
                   ]

class BVLCOrigUnicastNPDU(Packet):
    name = 'BVLC-ORIG-UNICAST-NPDU'
    fields_desc = [
                   PacketListField('plist', 
                                   BVLCBase(function='ORIGINAL_UNICAST_NPDU'), 
                                   BVLCBase)
                   ]

class BVLCOrigBroadcastNPDU(Packet):
    name = 'BVLC-ORIG-BROADCAST-NPDU'
    fields_desc = [
                   PacketListField('plist', 
                                   BVLCBase(function='ORIGINAL_BROADCAST_NPDU'), 
                                   BVLCBase),
                   ]


class NPDUDest(Packet):
    name = 'NPDU_DEST'
    fields_desc = [
                   ShortField('dnet', None),
                   FieldLenField('dlen', None, length_of='dadr', fmt='B'),
                   ConditionalField(FieldListField('dadr', None, XByteField('dadr_byte', None), 
                                                   length_from=lambda pkt:pkt.dlen), 
                                    lambda pkt: pkt.dadr is not None)
                   ]


class NPDUSource(Packet):
    name = 'NPDU_SOURCE'
    fields_desc = [
                   ShortField('snet', None),
                   FieldLenField('slen', None, length_of='sadr', fmt='B'),
                   FieldListField('sadr', None, XByteField('sadr_byte', None), 
                                  length_from=lambda pkt:pkt.slen)
                   ]


class NPDUBase(Packet):
    name = 'NPDU_BASE'
    fields_desc = [
                   ByteField('version', 1),
                   BitField('nlpci', 0b00000000, 8),
                   # @todo: use bit matching as condition
                   ConditionalField(PacketListField('dest', None, NPDUDest), 
                                    lambda pkt: pkt.hop_count is not None), 
                   ConditionalField(PacketListField('source', None, NPDUSource),
                                    lambda pkt: pkt.hop_count is not None),
                   ConditionalField(ByteField('hop_count', None), 
                                    lambda pkt: pkt.hop_count is not None)
                   ]


class NetworkLayerMessageType(Enum):
    WHO_IS_ROUTER_TO_NETWORK = 0x00
    I_AM_ROUTER_TO_NETWORK = 0x01

    
class NPDUContentBase(Packet):
    name = 'NPDU-CONTENT-BASE'
    fields_desc = [PacketListField('npdu',
                                   NPDUBase(nlpci=0b10000000),
                                   NPDUBase),
                   XByteField('message_type', None)]

    
class NPDUWhoIsRouterToNetworkContent(NPDUContentBase):
    name = 'NPDU-WHO-IS-ROUTER-TO-NETWORK-CONTENT'
    fields_desc = [PacketListField('npdu',
                                   NPDUBase(nlpci=0b10000000),
                                   NPDUBase),
                   XByteField('message_type', NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK),
                   ConditionalField(ShortField('network', None), 
                                    lambda pkt: pkt.network is not None)
                   ]


class NPDUIAmRouterToNetworkContent(NPDUContentBase):
    name = 'NPDU-I-AM-ROUTER-TO-NETWORK-CONTENT'
    fields_desc = [PacketListField('npdu',
                                   NPDUBase(nlpci=0b10000000),
                                   NPDUBase),
                   XByteField('message_type', NetworkLayerMessageType.I_AM_ROUTER_TO_NETWORK),
                   FieldListField('networks', None, ShortField('network', None))
                   ]

    
class NPDU(Packet):
    name = 'NPDU'
    fields_desc = [FieldLenField('length', None, length_of='content', adjust = lambda pkt,x:x+4),
                   PacketListField('content',
                                   None,
                                   NPDUContentBase,
                                   length_from=lambda pkt:pkt.length)
                   ]

    
def hexStringToIntList(hexStr):
    hexByteStrings = [hexStr[i:i+2] for i in range(0, len(hexStr), 2)]
    return [int(hexByteStr, 16) for hexByteStr in hexByteStrings]

    
def getNPDUBase(dest=None, source=None, hopCount=255):
    npduBase = {}
    nlpci = 0b10000000
    if dest:
        nlpci = nlpci | 0b00100000
        if dest.has_key('dlen') and dest.has_key('dadr'):
            log.warn('Both dlen and dadr not allowed in dest')
        if dest.has_key('dadr'):
            dest['dadr'] = hexStringToIntList(dest['dadr'])
        if dest.has_key('dlen'):
            if dest['dlen'] != 0:
                log.warn('Invalid dlen: %d, only 0 for BROADCAST allowed' % dest['dlen'])
        dest = NPDUDest(**dest)
        npduBase['dest'] = dest
        npduBase['hop_count'] = hopCount
    if source:
        nlpci = nlpci | 0b00001000
        if source.has_key('sadr'):
            source['sadr'] = hexStringToIntList(source['sadr'])
        source = NPDUSource(**source)
        npduBase['source'] = source
    npduBase['nlpci'] = nlpci
    npdu = NPDUBase(**npduBase)
    return npdu    


class BacDevStub(object):
    '''
    Very simple stub for a BACnet device.
    '''
    
    def __init__(self, srcIP=None, port=None, verb=0):
        if srcIP is None or port is None:
            tdIP, tdPort = BtfHelper.getTdIpAndPort()
        self.srcIpAddr = tdIP if srcIP is None else srcIP
        self.port = tdPort if port is None else port
        
        scapy_conf.verb=verb
#        scapy_conf.logLevel = 100
        
        bind_layers(UDP, BVLCBase, sport=port)
        bind_layers(UDP, BVLCBase, dport=port)
        
        self.ip = IP()
        self.ip.src = self.srcIpAddr
        self.udp = self.ip/UDP(sport=port, dport=port)

        
    def sendBvlcReadBdt(self, destIp):
        ip = IP()
        ip.src = self.srcIpAddr
        ip.dst = destIp
        send(ip/UDP(sport=self.port, dport=self.port)/BVLCReadBDT)

    def sendBvlcRegFd(self, destIp, ttl):
        ip = IP()
        ip.src = self.srcIpAddr
        ip.dst = destIp
        send(ip/UDP(sport=self.port, dport=self.port)/BVLCRegisterFD(time_to_live=ttl))
        
    
    def sendNpdu(self, destIp):
        ip = IP()
        ip.src = self.srcIpAddr
        ip.dst = destIp
        send(ip/UDP(sport=self.port, dport=self.port)/BVLCOrigUnicastNPDU()/NPDUBase())

    def getUDP(self, destIp):
        ip = IP()
        ip.src = self.srcIpAddr
        ip.dst = destIp
        return ip/UDP(sport=self.port, dport=self.port)
    
    def getBVLC(self, ipDest):
        if isinstance(ipDest, IPNetwork):
            udp = self.getUDP(str(ipDest.broadcast))
            bvlc = udp/BVLCOrigBroadcastNPDU()
        elif isinstance(ipDest, IPAddress):
            udp = self.getUDP(str(ipDest))
            bvlc = udp/BVLCOrigUnicastNPDU()
        else:
            raise ArgumentError('Invalid class for IP destination')
        return bvlc
    
    def sendIAmRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, nets=None):
        '''
        @type ipDest: IPNetwork for broadcast or IPAddress for unicast
        @param dest: NPDU destination
        @type dest: Dict with dnet (int) and dadr (string with hex MAC)
        @param source: NPDU source
        @type source: Dict with snet and sadr (string with hex MAC)
        '''
        
        content = NPDUIAmRouterToNetworkContent(npdu=getNPDUBase(dest, source, hopCount), 
                                                networks=nets)
        iAmRouterToNetwork = NPDU(content=content)
        p = self.getBVLC(ipDest)/iAmRouterToNetwork
        p.show2()
        send(p)
        
    def getWhoIsRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, net=None):
        content = NPDUWhoIsRouterToNetworkContent(npdu=getNPDUBase(dest, source, hopCount), 
                                                  network=net)
        whoIsRouterToNetwork = NPDU(content=content)
        p = self.getBVLC(ipDest)/whoIsRouterToNetwork
        return p
        
    def sendWhoIsRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, net=None):
        p = self.getWhoIsRouterToNetwork(ipDest, dest, source, hopCount, net)
        send(p)
        
    def whoIsRouterToNetwork(self, ipDest, dest=None, source=None, hopCount=255, net=None):
        p = self.getWhoIsRouterToNetwork(ipDest, dest, source, hopCount, net)
        ans, unans = sr(p, multi=True, timeout=3, verbose=3)
        for answer in ans:
            answer.summarize()
            

def readPCAP(path, port=47808):
    bind_layers(UDP, BVLCBase, sport=port)
    bind_layers(UDP, BVLCBase, dport=port)
    bind_layers(BVLCBase, NPDU,
                function=BvlcFunction.ORIGINAL_BROADCAST_NPDU)
    bind_layers(NPDU, NPDUContentBase)
    bind_layers(NPDU, NPDUBase)
    
    packets = rdpcap(path)
    packets.summary()
    for packet in packets:
        packet.summary()
        npdu = packet['NPDU']
        npdu.summary()
