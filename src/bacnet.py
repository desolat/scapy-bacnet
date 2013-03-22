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


import inspect

from scapy.all import *
from scapy.layers.inet import IP, UDP


BACNET_PORT = 47808


class Enum(object):
    _intern = object.__dict__.keys() + ['__module__', '__dict__', '__weakref__', '_intern']
    
    @classmethod
    def keys(cls):
        # introspection on __dict__ values does not work
#        keys = filter(lambda key: key not in cls._intern, 
#                      cls.__dict__.keys())
        members = inspect.getmembers(cls)
        keys = [key for key, value in members if (key not in cls._intern 
                                                  and not inspect.ismethod(value)
                                                  and not inspect.isfunction(value))]
        return keys

    @classmethod
    def values(cls):
        return [cls.__dict__[key] for key in cls.keys()]
    
    @classmethod
    def dict(cls):
        return dict(zip(cls.keys(), cls.values()))
    
    @classmethod
    def revDict(cls):
        return dict(zip(cls.values(), cls.keys()))
    

class BvlcFunction(Enum):
    RESULT = 0
    WRITE_BDT = 1
    READ_BDT = 2
    READ_BDT_ACK = 3
    FORWARDED_NPDU = 4
    REGISTER_FD = 5
    ORIGINAL_UNICAST_NPDU = 10
    ORIGINAL_BROADCAST_NPDU = 11


class BVLCConditional(Packet):
    name = 'BVLC-CONDITIONAL'
    fields_desc = [
                   ConditionalField(ShortField('time_to_live', None),
                                    lambda pkt: pkt.underlayer.function == BvlcFunction.REGISTER_FD),
                   ConditionalField(IPField('origin_ip', None), 
                                    lambda pkt: pkt.underlayer.function == BvlcFunction.FORWARDED_NPDU),
                   ConditionalField(ShortField('origin_port', 47808), 
                                    lambda pkt: pkt.underlayer.function == BvlcFunction.FORWARDED_NPDU)
                   ]
    
    def extract_padding(self, s):
        return "", s

    
#def calcBVLCLength(pkt, fieldLen):
#    length = 4
#    length += (len(pkt.time_to_live) if pkt.time_to_live is not None else 0)
#    length += (len(pkt.origin_ip) if pkt.origin_ip is not None else 0)
#    length += (len(pkt.origin_port) if pkt.origin_port is not None else 0)
#    length += len(pkt.payload)
#    return length

    
class BVLC(Packet):
    name = 'BVLC'
    fields_desc = [
                   XByteField('type', 0x81),
                   ByteEnumField('function', None, BvlcFunction.revDict()),

#                   LenField('length', None),
#                   FieldLenField('length', None, length_of='type',
#                                 adjust=calcBVLCLength), 
#                                 adjust=lambda pkt,x: 
#                                    x + \
#                                    3 + \
#                                    (len(pkt.time_to_live) if pkt.time_to_live is not None else 0) + \
#                                    (len(pkt.origin_ip) if pkt.origin_ip is not None else 0) + \
#                                    (len(pkt.origin_port) if pkt.origin_port is not None else 0) + \
#                                    len(pkt.payload)),
#                   ConditionalField(ShortField('time_to_live', None),
#                                    lambda pkt: pkt.function == BvlcFunction.REGISTER_FD),
#                   ConditionalField(IPField('origin_ip', None), 
#                                    lambda pkt: pkt.function == BvlcFunction.FORWARDED_NPDU),
#                   ConditionalField(ShortField('origin_port', 47808), 
#                                    lambda pkt: pkt.function == BvlcFunction.FORWARDED_NPDU),

                   FieldLenField('length', None, length_of='conditional', 
                                 adjust=lambda pkt,x: len(pkt.payload)+x+4),
                   PacketListField("conditional", [], BVLCConditional, 
                                   length_from=lambda pkt: pkt.length - len(pkt.payload) - 4)   
                   ]
    
#    def post_build(self, pkt, pay):
#        if self.length is None:
#            length = 4 + len(pay)
#            if self.time_to_live is not None:
#                length += 2
#            if self.origin_ip is not None: 
#                length += 4
#            if self.origin_port is not None:
#                length += 4
#            self.length = length
#        
#        return Packet.post_build(self, pkt, pay)

    def extract_padding(self, s):
        return "", s


class BVLCBase(Packet):
    name = 'BVLC-BASE'
    fields_desc = [XByteField('type', 0x81),
                   ByteEnumField('function', BvlcFunction.RESULT, BvlcFunction.revDict()),
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


class NetworkLayerMessageType(Enum):
    WHO_IS_ROUTER_TO_NETWORK = 0x00
    I_AM_ROUTER_TO_NETWORK = 0x01


class NPDU(Packet):
    name = 'NPDU'
    fields_desc = [
                   ByteField('version', 1),
                   BitField('nlpci', 0b00000000, 8),
                   # @todo: use bit matching as condition
                   ConditionalField(PacketListField('dest', None, NPDUDest), 
                                    lambda pkt: pkt.hop_count is not None), 
                   ConditionalField(PacketListField('source', None, NPDUSource),
                                    lambda pkt: pkt.hop_count is not None),
                   ConditionalField(ByteField('hop_count', None), 
                                    lambda pkt: pkt.hop_count is not None),
                   XByteField('message_type', None),
                   ConditionalField(ShortField('network', None), 
                                    lambda pkt: pkt.message_type == NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK)
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

    
class NPDUWithBVLCLength(Packet):
    name = 'NPDU-WITH-BVLC-LENGTH'
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



