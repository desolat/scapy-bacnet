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
    DISTRIBUTE_BROADCAST_TO_NETWORK = 9
    ORIGINAL_UNICAST_NPDU = 10
    ORIGINAL_BROADCAST_NPDU = 11


class BVLC(Packet):
    name = 'BVLC'
    fields_desc = [
                   XByteField('type', 0x81),
                   ByteEnumField('function', None, BvlcFunction.revDict()),
                   ShortField('length', None),
                   ConditionalField(ShortField('time_to_live', None),
                                    lambda pkt: pkt.function == BvlcFunction.REGISTER_FD),
                   ConditionalField(IPField('origin_ip', None), 
                                  lambda pkt: pkt.function == BvlcFunction.FORWARDED_NPDU),
                   ConditionalField(ShortField('origin_port', BACNET_PORT), 
                                    lambda pkt: pkt.function == BvlcFunction.FORWARDED_NPDU),
                   ]

    
    def post_build(self, pkt, pay):
        if self.length is None:
            length = len(pkt) + len(pay)
            pkt = pkt[:2] + struct.pack("!H", length) + pkt[4:]
        return pkt + pay


#     def extract_padding(self, s):
#         return "", s


class NPDUDest(Packet):
    name = 'NPDU_DEST'
    fields_desc = [
                   ShortField('dnet', None),
                   FieldLenField('dlen', None, length_of='dadr', fmt='B'),
                   ConditionalField(FieldListField('dadr', None, XByteField('dadr_byte', None), 
                                                   length_from=lambda pkt:pkt.dlen), 
                                    lambda pkt: pkt.dlen != 0 and pkt.dadr is not None)
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
                   BitField('nlpci', None, 8),
                   ConditionalField(PacketListField('dest', None, NPDUDest), 
                                    lambda pkt: pkt.nlpci & 0b00100000 != 0), 
                   ConditionalField(PacketListField('source', None, NPDUSource),
                                    lambda pkt: pkt.nlpci & 0b00001000 != 0),
                   ConditionalField(ByteField('hop_count', None), 
                                    lambda pkt: pkt.nlpci & 0b00100000 != 0),
                   ConditionalField(XByteField('message_type', None),
                                    lambda pkt: pkt.nlpci & 0b10000000 != 0),
                   ConditionalField(ShortField('network', None), 
                                    lambda pkt: pkt.message_type == NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK 
                                    and pkt.network is not None),
                   ConditionalField(FieldListField('networks', None, ShortField('network', None)),
                                    lambda pkt: pkt.message_type == NetworkLayerMessageType.I_AM_ROUTER_TO_NETWORK),
                   ]

                   
class PduType(Enum):
    UNCONFIRMED_REQUEST = 1
   
   
class UnconfirmedServiceChoice(Enum):
    WHO_IS = 8


class APDU(Packet):
    name = 'APDU'
    fields_desc = [
                   BitEnumField('pdu_type', None, 4, PduType.revDict()),
                   BitField('reserved', 0, 4),
                   ByteEnumField('service_choice', None, UnconfirmedServiceChoice.revDict())
                   ]
   

#     def post_build(self, pkt, pay):
#         '''
#         @fixme: NLPCI must be provided for conditionality calculation
#         '''
#         if self.nlpci is None:
#             if self.message_type is not None:
#                 nlpci = 0b10000000
#             if self.dest is not None:
#                 nlpci = nlpci | 0b00100000
#             if self.source is not None:
#                 nlpci = nlpci | 0b00001000
#             pkt = pkt[0] + struct.pack("!x", nlpci) + pkt[2:]
#          
#         return pkt + pay
        
    
def hexStringToIntList(hexStr):
    hexByteStrings = [hexStr[i:i+2] for i in range(0, len(hexStr), 2)]
    return [int(hexByteStr, 16) for hexByteStr in hexByteStrings]

    
def getNPDU(dest=None, source=None, hopCount=255):
    npdu = {}
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
        npdu['dest'] = dest
        npdu['hop_count'] = hopCount
    if source:
        nlpci = nlpci | 0b00001000
        if source.has_key('sadr'):
            source['sadr'] = hexStringToIntList(source['sadr'])
        source = NPDUSource(**source)
        npdu['source'] = source
    npdu['nlpci'] = nlpci
    npdu = NPDU(**npdu)
    return npdu    



