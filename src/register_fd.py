# -*- coding: UTF-8 -*-
'''
@since: 14.04.2014
@author: nuabaranda@web.de
@version: $Id$
'''

__version__ = "$Rev"
# $Source$


import logging
from optparse import OptionParser

from scapy.all import *
from scapy.layers.inet import IP, UDP
from netaddr.ip import IPNetwork, IPAddress

from bacnet import BvlcFunction, BVLC, BACNET_PORT


LOG = logging.getLogger()
TTL = 3600


def main():
    opts, args = parseCommandLine()
    if len(args) == 1: 
        dstAddr = IPAddress(args[0])
        srcAddr = None
    elif len(args) == 2:
        srcAddr = IPAddress(args[0])
        dstAddr = IPAddress(args[1]) 
    
    dstIfInfos = getIfaceInfo(dstAddr)
    if len(dstIfInfos) > 1:
        raise BaseException('Found more than one matching interface: %s' % dstIfInfos)
    if srcAddr is None:
        srcAddr = IPAddress(dstIfInfos[0].ip)
    if srcAddr == dstAddr:
        raise BaseException('Source address %s is equal to destination address %s' % (srcAddr, dstAddr))

    # http://osdir.com/ml/security.scapy.general/2007-11/msg00019.html
    conf.iface = dstIfInfos[0].name

    bind_layers(UDP, BVLC, sport=BACNET_PORT)
    bind_layers(UDP, BVLC, dport=BACNET_PORT)
    
    udp = IP(src=str(srcAddr), dst=str(dstAddr))/UDP(sport=BACNET_PORT, dport=BACNET_PORT)
    bvlc = udp/BVLC(function=BvlcFunction.REGISTER_FD, time_to_live=opts.ttl)
    bvlc.show2()
    send(bvlc)


def parseCommandLine():
    description = '''Send a Register_Foreign_Device BVLC request.

Uses the network interface which matches the destination.
'''
    usage = 'usage: %prog [src_addr] dst_addr [options]'
    parser = OptionParser(usage=usage, description=description)
    parser.add_option('--ttl', dest='ttl', default=3600, 
                      help='Time to live in seconds, default: %d' % TTL)
    (opts, args) = parser.parse_args()
    if len(args) < 1 or len(args) > 2:
        parser.error('Expecting 1 or 2 arguments')
    return opts, args
        

def getIfaceInfo(ipNetworkOrAddress):
    '''
    Determine interface information of the local interfaces an IP address or network belongs to.
    
    @param ipNetworkOrAddress: IP network or address matching the configured network of the wanted interfaces.
    '''

    if isinstance(ipNetworkOrAddress, IPAddress):
        LOG.info('Getting interface info for address %s' % str(ipNetworkOrAddress))
    elif isinstance(ipNetworkOrAddress, IPNetwork):
        LOG.info('Getting interface info for network %s' % ipNetworkOrAddress.ip)
    else:
        raise BaseException('ipNetworkOrAddress must be netaddr IPAddress or IPNetwork')
        
    matchingIfaceInfos = []
    for ifaceInfo in ifaces.itervalues():
        network = IPNetwork(str(ifaceInfo.dnetdict['addr']))
        netIps = list(network)
        if ipNetworkOrAddress in netIps:
            matchingIfaceInfos.append(ifaceInfo)

    if len(matchingIfaceInfos) == 0:
        raise BaseException('No interface with a matching IP settings found')
    return matchingIfaceInfos


if __name__ == "__main__":
    main()