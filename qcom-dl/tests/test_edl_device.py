import os

from conftest import *
from progress_callback_helpers import *

import qcomdl

## Tests

def test_edl_connections(edl):
    # try connecting to first available
    assert edl.connect()
    assert edl.isconnected()
    assert edl.disconnect()

    # try connecting via bus address
    devices = qcomdl.Edl.list_devices()
    assert isinstance(devices, list)
    assert len(devices) > 0
    device = devices[0]
    assert device
    edl2 = qcomdl.Edl()
    assert edl2.connect_bus_and_port(device["bus"], device["port"])
    assert edl2.isconnected()
    assert edl2.disconnect()

    # try connecting via full bus address
    edl3 = qcomdl.Edl()
    assert edl3.connect_bus_and_port_path(device["bus"], device["port_path"])
    assert edl3.isconnected()
    assert edl3.disconnect()

def test_sahara_device_info(sahara):
    dev_info = sahara.device_info()
    assert dev_info
    assert "serial" in dev_info
    assert "msm_id" in dev_info
    assert "pbl_sw" in dev_info
    assert "pk_hash" in dev_info

def test_sahara_upload(sahara, firehose_bin):
    assert os.path.exists(firehose_bin)
    assert sahara.upload(firehose_bin)
    assert sahara.done()

def test_firehose_ping(firehose):
    assert firehose.ping()
    assert firehose.ping()
    assert firehose.ping()

def test_firehose_configure(firehose):
    # before configuring, the names should be nonexistent
    assert not firehose.memory_name()
    assert not firehose.target_name()
    # after configuring, we should see the names the device provided
    assert firehose.configure()
    assert firehose.memory_name() == "eMMC"
    assert firehose.target_name() == "8936"
    # send a few pings for good measure
    assert firehose.ping()
    assert firehose.ping()

def test_firehose_program_skip_write(firehose, tmpdir, request):
    firehose.cfg_set_skip_write(1)  # this prevents us from actually writing to flash
    assert firehose.configure()
    ddir = tmpdir.mkdir('data')

    progress = PerFileProgressCallbacks()
    progress.register_callbacks(firehose)

    def zero_data_file(size):
        fname = "zero_%sb.dat" % size
        fpath = ddir.join(fname)
        with open(str(fpath), 'wb') as f:
            f.write("\x00" * size)
        request.addfinalizer(lambda: os.remove(str(fpath)))
        return str(fpath)

    progress.clear_file_vars()
    fname = zero_data_file(512)
    assert firehose.program(fname,  "0", "0", 1)
    progress.check_file_result(fname, 1)

    progress.clear_file_vars()
    fname = zero_data_file(512 + 100)
    assert firehose.program(fname,  "0", "0", 1)
    progress.check_file_result(fname, 2)

    progress.clear_file_vars()
    fname = zero_data_file(1024)
    assert firehose.program(fname,  "0", "0", 1)
    progress.check_file_result(fname, 2)

    progress.clear_file_vars()
    fname = zero_data_file(1024 + 100)
    assert firehose.program(fname,  "0", "0", 1)
    progress.check_file_result(fname, 3)

    progress.clear_file_vars()
    fname = zero_data_file(16384)
    assert firehose.program(fname,  "0", "0", 1)
    progress.check_file_result(fname, 32)

    progress.clear_file_vars()
    fname = zero_data_file(16384 + 100)
    assert firehose.program(fname,  "0", "0", 1)
    progress.check_file_result(fname, 33)

    progress.clear_file_vars()
    fname = zero_data_file(16384 * 2)
    assert firehose.program(fname,  "0", "0", 1)
    progress.check_file_result(fname, 64)

    progress.clear_file_vars()
    fname = zero_data_file((16384*2) + 100)
    assert firehose.program(fname,  "0", "0", 1)
    progress.check_file_result(fname, 65)

    empty = str(ddir.join("empty.dat"))
    with open(empty, 'wb') as f:
        f.write("")
    progress.clear_file_vars()
    assert firehose.program(empty, "0", "0", 1)
    progress.check_file_result(empty, 0)

    progress.check_totals(202)
    assert(progress.filenames_collected_at_start == progress.filenames_collected_at_end)
    assert(empty in progress.filenames_collected_at_end)
    progress.filenames_collected_at_end.remove(empty)
    assert(progress.filenames_collected_in_progress == progress.filenames_collected_at_end)

    # negative test to verify that exceptions thrown from progress callbacks get caught
    class throwup_exception(Exception):
        pass

    def throwup_start_file_callback(fname, sectors_to_be_written):
        raise throwup_exception('barf!')

    firehose.register_file_progress_callbacks(throwup_start_file_callback, None, None)
    with pytest.raises(throwup_exception):
        firehose.program(empty, "0", "0", 1)

def test_firehose_getsha256digest(firehose):
    # TODO: getsha256digest just prints the digest to stdout for now
    # maybe make this more useful at some point
    assert firehose.getsha256digest(1, "0", "0")

def test_firehose_benchmark(firehose):
    assert firehose.benchmark(1000, 5000)
    assert firehose.ping()

def test_firehose_patch(firehose):
    # We have to YOLO this test. SkipWrite=1 does NOT actually prevent writing patch values.
    # It only affects progam commands.
    # TODO: implement undocumented <read> command so we can try to restore data here
    assert firehose.getsha256digest(1, "0", "0")
    firehose.patch("0", "0", "4", "0", "1", "Test Patch")
    assert firehose.getsha256digest(1, "0", "0")
    firehose.patch("0", "0", "4", "0", "0", "Test Patch")
    assert firehose.getsha256digest(1, "0", "0")

def test_run(firehose, zero_flashables_dir):
    progress = PerFileProgressCallbacks()
    progress.register_callbacks(firehose)
    res =  firehose.run(zero_flashables_dir,
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

def test_run_percent_progress(firehose, zero_flashables_dir):
    progress = PercentProgressCallbacks()
    image_size = qcomdl.total_image_sectors_non_vip(zero_flashables_dir, FLASHABLE_PROGRAM_XML)
    progress.register_callbacks(firehose, image_size)
    res =  firehose.run(zero_flashables_dir,
                        FLASHABLE_PROGRAM_XML,
                        FLASHABLE_PATCH_XML,
                        True,
                        False,
                        False,
                        1)

    assert res
    assert len(progress.called_values) in range(1, ZERO_FLASHABLE_SECTORS_COUNT)
    assert progress.called_values[0] in range(0, 100)
    assert progress.called_values[-1] == 100

def test_run_flash(squid_device, zero_flashables_with_mbn):
    assert(squid_device.bootIntoEDL())
    progress = PercentProgressCallbacks()
    qcomdl.FlashDevice.flash(zero_flashables_with_mbn,
                             percent_progress_callback=progress.handle_percent)

    assert len(progress.called_values) in range(1, ZERO_FLASHABLE_SECTORS_COUNT)
    assert progress.called_values[0] in range(0, 100)
    assert progress.called_values[-1] == 100

def test_firehose_rpmb_erase(firehose):
    assert firehose.rpmb_erase()

