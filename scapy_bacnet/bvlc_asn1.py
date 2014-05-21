# -*- coding: UTF-8 -*-
'''
@since: 18.03.2013
@author: nuabaranda@web.de
'''


from scapy.all import *


class ASN1_Class_BVLC(ASN1_Class_UNIVERSAL):
    name = 'BVLC'
    PDU_RESULT = 0x00
    PDU_WRITE_BDT = 0x01


class ASN1_BVLC_PDU_RESULT(ASN1_SEQUENCE):
    tag = ASN1_Class_BVLC.PDU_RESULT

class BERcodec_BVLC_PDU_RESULT(BERcodec_SEQUENCE):
    tag = ASN1_Class_BVLC.PDU_RESULT

class ASN1F_BVLC_PDU_RESULT(ASN1F_SEQUENCE):
    tag = ASN1_Class_BVLC.PDU_RESULT

BVLC_result_code = {0x0000 : 'Success',
                    0x0010 : 'WRITE-BDT-NAK',
                    0x0020 : 'READ-BDT-NAK',
                    0x0030 : 'REGISTER-FD-NAK',
                    0x0040 : 'READ-FDT-NAK',
                    0x0050 : 'DELETE-FDT-NAK',
                    0x0060 : 'DISTRIBUTE-BROADCAST-TO-NETWORK-NAK'}

class ASN1P_BVLCresult(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_BVLC_PDU_RESULT(ASN1F_INTEGER('function', ASN1_Class_BVLC.PDU_RESULT),
#                                      ASN1F_field('length'),
                                      ASN1F_enum_INTEGER('result_code', 0x0000, BVLC_result_code))


class ASN1P_BVLC(ASN1_Packet):
    ASN1_codec = ASN1_Codecs.BER
    ASN1_root = ASN1F_SEQUENCE(
                               ASN1F_INTEGER('type', 0x81),
                               ASN1F_CHOICE('PDU', None, ASN1P_BVLCresult)
                               )
