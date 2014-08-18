# -*- coding: UTF-8 -*-
'''
@since: 12.08.2014
'''


import pytest

from bacnet import readPcap


@pytest.fixture
def pcap_path():
    return 'who_has_i_have.pcap'


@pytest.mark.usefixtures('bind_apdu')
def test_read_pcap(pcap_path):
    readPcap(pcap_path)


