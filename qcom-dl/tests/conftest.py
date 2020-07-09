import pytest
import os
import time
import gzip
import shutil
from zipfile import ZipFile

from squid_common import SquidDevice
from squid_common import AndroidBuild
from squid_common import logit

from sample_data_helpers import *

import qcomdl

FLASHABLE_PROGRAM_XML = "rawprogram_unsparse.xml"
FLASHABLE_PATCH_XML = "patch0.xml"
FLASHABLE_VIP_XML = "vip_commands.xml"
FLASHABLE_SIGNED_DIGESTS_MBN = "signed_digest_table.mbn"
FLASHABLE_CHAINED_DIGESTS_BIN = "chained_digests.bin"

FIREHOSE_GZ = sample_path('prog_emmc_firehose_8936.mbn.gz')
VIP_FIREHOSE_GZ = sample_path('validated_emmc_firehose_8936.mbn.gz')
ZERO_FLASHABLE_ZIP = sample_path('zero_flashables.zip')
ZERO_FLASHABLE_SECTORS_COUNT = 11 # expected count of sectors for the test image
ZERO_FLASHABLE_MR_ZIP = sample_path('zero_flashables_mr.zip')

EDL_VIP_DEVICE_FLASHABLE_ZIP = sample_path('edl_vip_device_image.zip')

@pytest.fixture(scope='session')
def squid_device(request):
    dut = SquidDevice()
    request.addfinalizer(lambda: dut.resetPower())
    return dut


@pytest.fixture(scope='session')
def zero_flashables_dir(tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp('zero_flashables').strpath
    with ZipFile(ZERO_FLASHABLE_ZIP, 'r') as zip:
        zip.extractall(str(tmpdir))
    return tmpdir


@pytest.fixture(scope='session')
def zero_flashables_mr_zip(tmpdir_factory):
    """
    Same contents as ZERO_FLASHABLE_ZIP, but with everything under the
    full/flashables/ subdirectories & intended to be passed to qcomdl
    without unzipping.
    """
    return ZERO_FLASHABLE_MR_ZIP


@pytest.fixture(scope='session')
def edl_vip_device_flashables_dir(tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp('edl_vip_device_flashables').strpath
    with ZipFile(EDL_VIP_DEVICE_FLASHABLE_ZIP, 'r') as zip:
        zip.extractall(str(tmpdir))
    return tmpdir


@pytest.fixture(scope='session')
def firehose_bin(tmpdir_factory, request):
    fname = tmpdir_factory.mktemp('firehose').join("firehose.mbn")
    print fname
    f = gzip.open(FIREHOSE_GZ, 'rb')
    try:
        with open(str(fname), 'wb') as outf:
            shutil.copyfileobj(f, outf)
    finally:
        f.close()
    request.addfinalizer(lambda: os.remove(str(fname)))
    return str(fname)


@pytest.fixture(scope='session')
def zero_flashables_with_mbn(request, firehose_bin, zero_flashables_dir):
    dest = str(os.path.join(zero_flashables_dir, qcomdl.FIREHOSE_DEFAULT_BIN_APQ8039))
    shutil.copyfile(firehose_bin, dest)
    request.addfinalizer(lambda: os.remove(dest))
    return zero_flashables_dir


@pytest.fixture(scope='function')
def edl(request, squid_device):
    assert squid_device.bootIntoEDL()
    edl = qcomdl.Edl()
    def _disconnect_edl():
        if edl.isconnected():
            edl.disconnect()
    request.addfinalizer(_disconnect_edl)
    return edl


@pytest.fixture(scope='function')
def sahara(edl):
    assert edl.connect()
    assert edl.isconnected()
    return qcomdl.Sahara(edl)


@pytest.fixture(scope='function')
def firehose(edl, firehose_bin):
    assert edl.connect()
    assert edl.isconnected()
    sahara = qcomdl.Sahara(edl)
    assert sahara.upload(firehose_bin)
    assert sahara.done()
    # obligatory sleep as firehose comes up
    logit("[Info] Sleeping 3 seconds while firehose comes up...")
    time.sleep(3)
    return qcomdl.Firehose(edl)


@pytest.fixture(scope='session')
def vip_firehose_bin(tmpdir_factory, request):
    fname = tmpdir_factory.mktemp('firehose').join("vip_firehose.mbn")
    print fname
    f = gzip.open(VIP_FIREHOSE_GZ, 'rb')
    try:
        with open(str(fname), 'wb') as outf:
            shutil.copyfileobj(f, outf)
    finally:
        f.close()
    request.addfinalizer(lambda: os.remove(str(fname)))
    return str(fname)


@pytest.fixture(scope='session')
def vip_flashables_with_mbn(request, vip_firehose_bin, edl_vip_device_flashables_dir):
    dest = str(os.path.join(edl_vip_device_flashables_dir, qcomdl.FIREHOSE_DEFAULT_VIP_BIN_APQ8039))
    shutil.copyfile(vip_firehose_bin, dest)
    request.addfinalizer(lambda: os.remove(dest))
    return edl_vip_device_flashables_dir


@pytest.fixture(scope='function')
def vip_firehose(squid_device, request, vip_firehose_bin):
    assert squid_device.bootIntoEDL()
    edl = qcomdl.Edl()
    def _disconnect_edl():
        if edl.isconnected():
            edl.disconnect()
    request.addfinalizer(_disconnect_edl)
    assert edl.connect()
    assert edl.isconnected()
    sahara = qcomdl.Sahara(edl)
    assert sahara.upload(vip_firehose_bin)
    assert sahara.done()
    # obligatory sleep as firehose comes up
    logit("[Info] Sleeping 3 seconds while firehose comes up...")
    time.sleep(3)
    return qcomdl.Firehose(edl)

