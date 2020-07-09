import pytest
from conftest import *
import re

import qcomdl

def test_has_version():
    assert re.match("^\d+\.\d+\.\d+$", qcomdl.version())

def test_edl_device_listing():
    dev_list = qcomdl.Edl.list_devices()
    assert isinstance(dev_list, list)

def test_total_image_sectors_vip_counts_correctly(zero_flashables_dir):
    assert qcomdl.total_image_sectors_vip(zero_flashables_dir, FLASHABLE_VIP_XML) == ZERO_FLASHABLE_SECTORS_COUNT

def test_total_image_sectors_vip_bad_zip_xml_fails(zero_flashables_dir):
    with pytest.raises(qcomdl.error):
        qcomdl.total_image_sectors_vip(zero_flashables_dir, FLASHABLE_PROGRAM_XML)
    with pytest.raises(qcomdl.error):
        qcomdl.total_image_sectors_vip(zero_flashables_dir, 'nonexistent.xml')
    with pytest.raises(qcomdl.error):
        qcomdl.total_image_sectors_vip('nonexistent_dir', 'nonexistent.xml')

def test_total_image_sectors_vip_counts_empty_image_correctly(edl_vip_device_flashables_dir):
    assert qcomdl.total_image_sectors_vip(edl_vip_device_flashables_dir, FLASHABLE_VIP_XML) == 0

def test_total_image_sectors_non_vip_counts_correctly(zero_flashables_dir):
    assert qcomdl.total_image_sectors_non_vip(zero_flashables_dir, FLASHABLE_PROGRAM_XML) == ZERO_FLASHABLE_SECTORS_COUNT

def test_total_image_sectors__non_vip_bad_zip_xml_fails(zero_flashables_dir):
    with pytest.raises(qcomdl.error):
        qcomdl.total_image_sectors_non_vip(zero_flashables_dir, FLASHABLE_VIP_XML)
    with pytest.raises(qcomdl.error):
        qcomdl.total_image_sectors_non_vip(zero_flashables_dir, 'nonexistent.xml')
    with pytest.raises(qcomdl.error):
        qcomdl.total_image_sectors_non_vip('nonexistent_dir', 'nonexistent.xml')

