import pytest
import qcomdl

from conftest import *
from progress_callback_helpers import *

## Tests

def test_firehose_vip(vip_firehose, edl_vip_device_flashables_dir):
    progress = PerFileProgressCallbacks()
    progress.register_callbacks(vip_firehose)
    assert vip_firehose.run_vip(edl_vip_device_flashables_dir, FLASHABLE_VIP_XML, FLASHABLE_SIGNED_DIGESTS_MBN, FLASHABLE_CHAINED_DIGESTS_BIN)
    progress.check_totals(0)
    assert(len(progress.filenames_collected_at_start) == 0)
    assert(len(progress.filenames_collected_at_end) == 0)
    assert(len(progress.filenames_collected_in_progress) == 0)

def test_firehose_ping_fails(vip_firehose):
    # ping will fail because it is not part of the vip configuration
    with pytest.raises(qcomdl.error):
        vip_firehose.ping()

def test_run_vip_flashing_zeros(vip_firehose, zero_flashables_dir):
    progress = PerFileProgressCallbacks()
    progress.register_callbacks(vip_firehose)
    assert vip_firehose.run_vip(zero_flashables_dir, FLASHABLE_VIP_XML, FLASHABLE_SIGNED_DIGESTS_MBN, FLASHABLE_CHAINED_DIGESTS_BIN)
    progress.check_totals(ZERO_FLASHABLE_SECTORS_COUNT)
    emptyfile = os.path.join(zero_flashables_dir, 'zero0k.bin')
    assert(emptyfile not in progress.filenames_collected_at_start) # vip generator prunes it out
    assert(progress.filenames_collected_at_start == progress.filenames_collected_at_end)
    assert(progress.filenames_collected_in_progress == progress.filenames_collected_at_end)

def test_firehose_vip_percent_progress(vip_firehose, edl_vip_device_flashables_dir):
    progress = PercentProgressCallbacks()
    progress.register_callbacks(vip_firehose, 0)
    assert vip_firehose.run_vip(edl_vip_device_flashables_dir, FLASHABLE_VIP_XML, FLASHABLE_SIGNED_DIGESTS_MBN, FLASHABLE_CHAINED_DIGESTS_BIN)
    assert len(progress.called_values) == 0

def test_run_vip_flashing_zeros_percent_progress(vip_firehose, zero_flashables_dir):
    progress = PercentProgressCallbacks()
    progress.register_callbacks(vip_firehose, ZERO_FLASHABLE_SECTORS_COUNT)
    assert vip_firehose.run_vip(zero_flashables_dir, FLASHABLE_VIP_XML, FLASHABLE_SIGNED_DIGESTS_MBN, FLASHABLE_CHAINED_DIGESTS_BIN)
    assert len(progress.called_values) in range(1, ZERO_FLASHABLE_SECTORS_COUNT)
    assert progress.called_values[0] in range(0, 100)
    assert progress.called_values[-1] == 100

def test_run_flash_vip(squid_device, vip_flashables_with_mbn):
    assert(squid_device.bootIntoEDL())
    qcomdl.FlashDevice.flash_vip(vip_flashables_with_mbn)
