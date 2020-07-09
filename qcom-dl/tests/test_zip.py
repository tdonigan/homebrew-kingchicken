from conftest import *
from progress_callback_helpers import *

import qcomdl

## Tests

def test_run_zip(firehose, zero_flashables_mr_zip):
    progress = PerFileProgressCallbacks()
    progress.register_callbacks(firehose)
    res =  firehose.run(zero_flashables_mr_zip,
                        FLASHABLE_PROGRAM_XML,
                        FLASHABLE_PATCH_XML,
                        True,
                        False,
                        False,
                        1)

    assert res
    progress.check_totals(ZERO_FLASHABLE_SECTORS_COUNT)
    assert(progress.filenames_collected_at_start == progress.filenames_collected_at_end)
    assert('zero0k.bin' in progress.filenames_collected_at_end)
    progress.filenames_collected_at_end.remove('zero0k.bin')
    assert(progress.filenames_collected_in_progress == progress.filenames_collected_at_end)


def test_run_vip_zip(vip_firehose, zero_flashables_mr_zip):
    progress = PerFileProgressCallbacks()
    progress.register_callbacks(vip_firehose)
    assert vip_firehose.run_vip(zero_flashables_mr_zip, FLASHABLE_VIP_XML, FLASHABLE_SIGNED_DIGESTS_MBN, FLASHABLE_CHAINED_DIGESTS_BIN)
    progress.check_totals(ZERO_FLASHABLE_SECTORS_COUNT)
    assert('zero0k.bin' not in progress.filenames_collected_at_start) # vip generator prunes it out
    assert(progress.filenames_collected_at_start == progress.filenames_collected_at_end)
    assert(progress.filenames_collected_in_progress == progress.filenames_collected_at_end)


def test_run_flash_zip(squid_device, zero_flashables_mr_zip):
    assert(squid_device.bootIntoEDL())
    progress = PercentProgressCallbacks()
    qcomdl.FlashDevice.flash(zero_flashables_mr_zip,
                             percent_progress_callback=progress.handle_percent)

    assert len(progress.called_values) in range(1, ZERO_FLASHABLE_SECTORS_COUNT)
    assert progress.called_values[0] in range(0, 100)
    assert progress.called_values[-1] == 100


def test_run_flash_vip_zip(squid_device, zero_flashables_mr_zip):
    assert(squid_device.bootIntoEDL())
    qcomdl.FlashDevice.flash_vip(zero_flashables_mr_zip)
