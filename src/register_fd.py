# -*- coding: UTF-8 -*-
'''
@since: 14.04.2014
@author: nuabaranda@web.de
'''

__version__ = ""
# $Source$


import os.path

from scapy.all import *
from scapy.layers.inet import IP, UDP
# from netaddr.ip import IPNetwork, IPAddress

from bacnet import BvlcFunction, BVLC, BACNET_PORT, NPDU, NetworkLayerMessageType, NPDUSource,\
    NPDUDest, hexStringToIntList

# @todo: add a command line interface for parameters
SRC_IP = '192.168.89.1'
DST_IP = '168.152.32.39'
TTL = 3600

# http://osdir.com/ml/security.scapy.general/2007-11/msg00019.html
show_interfaces()
# @todo: set used interface according to destination IP
#for ifaceName, ifaceInfo in ifaces.iteritems():
conf.iface = "eth6"

bind_layers(UDP, BVLC, sport=BACNET_PORT)
bind_layers(UDP, BVLC, dport=BACNET_PORT)

udp = IP(src=SRC_IP, dst=DST_IP)/UDP(sport=BACNET_PORT, dport=BACNET_PORT)
bvlc = udp/BVLC(function=BvlcFunction.REGISTER_FD, time_to_live=TTL)
bvlc.show2()
send(bvlc)