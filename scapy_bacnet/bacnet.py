# -*- coding: UTF-8 -*-
'''
BACnet device stub to simulate some behavior.

Evolution steps:

1) Faked packets (e.g. fake remote device requests).
2) @todo: Fake device behavior (e.g. automatically answer requests).

@since: 21.11.2012
@author: nuabaranda@web.de
'''


import inspect
import logging

from netaddr.ip import IPNetwork, IPAddress

# Set log level to benefit from Scapy warnings
logging.getLogger("scapy").setLevel(1)

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
                   # optional destination
#                    ConditionalField(PacketListField('dest', None, NPDUDest),
#                                     lambda pkt: pkt.nlpci & 0b00100000 != 0),
                   ConditionalField(ShortField('dnet', None),
                                    lambda pkt: pkt.nlpci & 0b00100000 != 0),
                   ConditionalField(FieldLenField('dlen', None, length_of='dadr', fmt='B'),
                                    lambda pkt: pkt.nlpci & 0b00100000 != 0),
                   ConditionalField(FieldListField('dadr', None, XByteField('dadr_byte', None),
                                                   length_from=lambda pkt:pkt.dlen),
                                    lambda pkt: pkt.nlpci & 0b00100000 != 0
                                        and pkt.dlen != 0
                                        and pkt.dadr is not None),
                   # optional source
#                    ConditionalField(PacketListField('source', None, NPDUSource),
#                                     lambda pkt: pkt.nlpci & 0b00001000 != 0),
                   ConditionalField(ShortField('snet', None),
                                    lambda pkt: pkt.nlpci & 0b00001000 != 0),
                   ConditionalField(FieldLenField('slen', None, length_of='sadr', fmt='B'),
                                    lambda pkt: pkt.nlpci & 0b00001000 != 0),
                   ConditionalField(FieldListField('sadr', None, XByteField('sadr_byte', None),
                                                   length_from=lambda pkt:pkt.slen),
                                    lambda pkt: pkt.nlpci & 0b00001000 != 0),

                   ConditionalField(ByteField('hop_count', None),
                                    lambda pkt: pkt.nlpci & 0b00100000 != 0),
                   ConditionalField(XByteField('message_type', None),
                                    lambda pkt: pkt.nlpci & 0b10000000 != 0),
                   ConditionalField(
                                    ShortField('network', None),
                                    lambda pkt: pkt.message_type == NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK
                                        and pkt.network is not None
                                    ),
                   ConditionalField(FieldListField('networks', None, ShortField('network', None)),
                                    lambda pkt: pkt.message_type == NetworkLayerMessageType.I_AM_ROUTER_TO_NETWORK),
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


#     def post_dissect(self, s):
#         return s


    def extract_padding(self, s):
        if s != '' and self.message_type == NetworkLayerMessageType.WHO_IS_ROUTER_TO_NETWORK:
            network = struct.unpack('!H', s)[0]
            self.network = network
            s = ''
        return s, None


class PduType(Enum):
    CONFIRMED_REQUEST = 0
    UNCONFIRMED_REQUEST = 1
    SIMPLE_ACK = 2
    COMPLEX_ACK = 3
    SEGMENT_ACK = 4
    ERROR = 5
    REJECT = 6
    ABORT = 7


class UnconfirmedServiceChoice(Enum):
    I_AM = 0
    I_HAVE = 1
    UNCONFIRMED_COV_NOTIFICATION = 2
    UNCONFIRMED_EVENT_NOTIFICATION = 3
    UNCONFIRMED_PRIVATE_TRANSFER = 4
    UNCONFIRMED_TEXT_MESSAGE = 5
    TIME_SYNCHRONIZATION = 6
    WHO_HAS = 7
    WHO_IS = 8
    UTC_TIME_SYNCHRONIZATION = 9


class APDU(Packet):
    name = 'APDU'
    fields_desc = [
                   BitEnumField('pdu_type', None, 4, PduType.revDict()),
                   BitField('reserved', 0, 4),
                   ByteEnumField('service_choice', None, UnconfirmedServiceChoice.revDict())
                   ]


def bindLayers():
    bind_layers(UDP, BVLC, sport=BACNET_PORT)
    bind_layers(UDP, BVLC, dport=BACNET_PORT)
    bind_layers(BVLC, NPDU)
    bind_layers(NPDU, APDU)


def getBvlcBase(ipDest):
    bvlcBase = {}
    if isinstance(ipDest, IPNetwork):
        function = BvlcFunction.ORIGINAL_BROADCAST_NPDU
    elif isinstance(ipDest, IPAddress):
        function = BvlcFunction.ORIGINAL_UNICAST_NPDU
    else:
        raise Scapy_Exception('Invalid class for IP destination')
    bvlcBase['function'] = function
    return bvlcBase


def getNpduBase(dest=None, source=None, hopCount=255, withApdu=False):
    npduContent = {'nlpci' : getNlpci(dest, source, withApdu)}
    if dest:
        npduContent['dest'] = getNpduDest(dest)
        npduContent['hop_count'] = hopCount
    if source:
        npduContent['source'] = getNpduSource(source)
    return npduContent


def getNlpci(dest=None, source=None, withApdu=False):
    if withApdu:
        nlpci = 0b00000000
    else:
        nlpci = 0b10000000
    if dest:
        nlpci = nlpci | 0b00100000
    if source:
        nlpci = nlpci | 0b00001000
    return nlpci


def getNpduDest(dest):
    if dest.has_key('dlen') and dest.has_key('dadr'):
        log.warn('Both dlen and dadr not allowed in dest')
    if dest.has_key('dadr'):
        dest['dadr'] = hexStringToIntList(dest['dadr'])
    if dest.has_key('dlen'):
        if dest['dlen'] != 0:
            log.warn('Invalid dlen: %d, only 0 for BROADCAST allowed' % dest['dlen'])
    dest = NPDUDest(**dest)
    return dest


def getNpduSource(source):
    if source.has_key('sadr'):
        source['sadr'] = hexStringToIntList(source['sadr'])
    source = NPDUSource(**source)
    return source


def hexStringToIntList(hexStr):
    hexByteStrings = [hexStr[i:i + 2] for i in range(0, len(hexStr), 2)]
    return [int(hexByteStr, 16) for hexByteStr in hexByteStrings]


def sendWhoIs(src, dst, count=1):
    '''
    @param dst: Destination IP or network 
    @todo: Use matching interface IP as src
    '''

    bindLayers()

    try:
        ipDst = IPNetwork(dst)
        dst = str(ipDst.broadcast)
    except:
        ipDst = IPAddress(dst)

    udp = IP(src=src, dst=dst) / UDP(sport=BACNET_PORT, dport=BACNET_PORT)
    bvlcBase = getBvlcBase(ipDst)
    bvlc = udp / BVLC(**bvlcBase)
    npduBase = getNpduBase(withApdu=True)
    npdu = bvlc / NPDU(**npduBase)
    apdu = npdu / APDU(pdu_type=PduType.UNCONFIRMED_REQUEST,
                       service_choice=UnconfirmedServiceChoice.WHO_IS)
    send(apdu, count=count)


def visualizeRoundTripTimes(pcapPath):
    bindLayers()

    packets = getPackets(pcapPath)
    rtts = getRoundTripTimes(packets)
    rttsInMs = [rtt * 1000 for rtt in rtts]
    from matplotlib import pyplot
    pyplot.hist(rttsInMs, bins=40)
    pyplot.title('DDC4200e, 1.12.2#464, Who-Has, Round-trip time distribution, No. of samples: %d' % len(rttsInMs))
#     pyplot.ylabel('No. of conversations')
    pyplot.xlabel('RTT (ms)')
    pyplot.show()


def getPackets(pcapPath):
    packets = rdpcap(pcapPath)
    packets.summary()
    return packets


def getRoundTripTimes(packets):
    rtts = []
    reqTime = None
    replTime = None
    for i, packet in enumerate(packets):
        packet.summary()
        bvlc = packet['BVLC']
        npdu = packet['NPDU']
        npdu.summary()
        if packet.haslayer('APDU'):
            apdu = packet['APDU']
            timestamp = packet.time
            if apdu.fields['service_choice'] in (UnconfirmedServiceChoice.WHO_HAS,
                                                 UnconfirmedServiceChoice.WHO_IS):
                if reqTime is not None:
                    log.warn('No reply for request')
                reqTime = timestamp
            elif apdu.fields['service_choice'] in (UnconfirmedServiceChoice.I_HAVE,
                                                   UnconfirmedServiceChoice.I_AM):
                if reqTime is None:
                    log.warn('No request for reply')
                    continue
                replTime = timestamp
                diff = replTime - reqTime
                rtts.append(diff)
                reqTime = None
                replTime = None
    return rtts


if __name__ == "__main__":
    interact(mydict=globals(), mybanner='BACnet')
