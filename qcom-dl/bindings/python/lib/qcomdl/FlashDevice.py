import logging
import os
import time

import qcomdl


class QcomdlPercentProgressLogger:
    def __init__(self, granularity=1):
        self.logger = logging.getLogger(__name__)
        self.granularity = granularity

    def handle_percent(self, percent):
        if (percent % self.granularity) == 0:
            self.logger.info("qcomdl flashing %d%% complete" % percent)


DEFAULT_PCT_LOGGING_GRANULARITY = 10
DEFAULT_LOGGER = QcomdlPercentProgressLogger(granularity=DEFAULT_PCT_LOGGING_GRANULARITY)


def flash(flashable_path, percent_progress_callback=DEFAULT_LOGGER.handle_percent):
    assert os.path.exists(flashable_path)
    qcomdl.set_loglevel(qcomdl.QCOMDL_LOG_LEVEL_WARNING)
    edl = qcomdl.Edl()
    assert edl.connect()
    try:
        firehose_bin = qcomdl.get_firehose_bin(flashable_path)
        assert firehose_bin, "No firehose binary found"

        sahara = qcomdl.Sahara(edl)
        assert sahara.upload(flashable_path, firehose_bin)
        assert sahara.done()
        time.sleep(3)
        firehose = qcomdl.Firehose(edl)
        image_sectors = qcomdl.total_image_sectors_non_vip(flashable_path, qcomdl.FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME)
        firehose.register_percent_progress_callbacks(percent_progress_callback, image_sectors)
        try:
            assert firehose.program_from_file(flashable_path, qcomdl.FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME, 0)
            assert firehose.patch_from_file(flashable_path, qcomdl.FIREHOSE_DEFAULT_PATCH_XML_FILENAME)
        finally:
            firehose.soft_reset(qcomdl.FIREHOSE_DEFAULT_RESET_DELAY_SECS)
    finally:
        edl.disconnect()


def flash_vip(flashable_path, percent_progress_callback=DEFAULT_LOGGER.handle_percent):
    assert os.path.exists(flashable_path)
    qcomdl.set_loglevel(qcomdl.QCOMDL_LOG_LEVEL_WARNING)
    edl = qcomdl.Edl()
    assert edl.connect()
    try:
        sahara = qcomdl.Sahara(edl)
        assert sahara.upload(flashable_path, qcomdl.FIREHOSE_DEFAULT_VIP_BIN_APQ8039)
        assert sahara.done()
        time.sleep(3)
        firehose = qcomdl.Firehose(edl)
        vip_image_sectors = qcomdl.total_image_sectors_vip(flashable_path, qcomdl.FIREHOSE_DEFAULT_VIP_XML_FILENAME)
        firehose.register_percent_progress_callbacks(percent_progress_callback, vip_image_sectors)
        assert firehose.run_vip(flashable_path,
                                qcomdl.FIREHOSE_DEFAULT_VIP_XML_FILENAME,
                                qcomdl.FIREHOSE_DEFAULT_DIGEST_TABLE_FILENAME,
                                qcomdl.FIREHOSE_DEFAULT_CHAINED_DIGESTS_FILENAME)
    finally:
        edl.disconnect()
