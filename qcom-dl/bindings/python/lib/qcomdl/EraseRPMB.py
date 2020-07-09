import os
import time

import qcomdl


def erase_rpmb(flashable_path):
    assert os.path.exists(flashable_path)

    firehose_bin = qcomdl.get_firehose_bin(flashable_path)
    assert firehose_bin, "No firehose binary found"

    qcomdl.set_loglevel(qcomdl.QCOMDL_LOG_LEVEL_WARNING)

    edl = qcomdl.Edl()
    assert edl.connect()

    try:
        sahara = qcomdl.Sahara(edl)
        assert sahara.upload(firehose_bin)
        assert sahara.done()
        time.sleep(3)
        firehose = qcomdl.Firehose(edl)
        try:
            assert firehose.configure()
            assert firehose.ping()
            assert firehose.rpmb_erase()
        finally:
            firehose.soft_reset(qcomdl.FIREHOSE_DEFAULT_RESET_DELAY_SECS)
    finally:
        edl.disconnect()
