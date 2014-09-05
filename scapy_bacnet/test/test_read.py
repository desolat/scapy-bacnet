# -*- coding: UTF-8 -*-
'''
@since: 12.08.2014
'''


import pytest

from bacnet import visualizeRountTripTimes


@pytest.fixture
def pcap_path():
    return 'who_has_i_have.pcap'


@pytest.mark.usefixtures('bind_apdu')
def test_visualizeRountTripTimes(pcap_path):
    visualizeRountTripTimes(pcap_path)


