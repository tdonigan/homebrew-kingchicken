from os import path

from FlashDevice import flash, flash_vip
from EraseRPMB import erase_rpmb
from _qcomdl_native import *


def get_firehose_bin(flashable_path):
    firehose_bin_apq8039 = path.join(flashable_path, FIREHOSE_DEFAULT_BIN_APQ8039)
    firehose_bin_sda660 = path.join(flashable_path, FIREHOSE_DEFAULT_BIN_SDA660)

    if path.exists(firehose_bin_apq8039):
        return firehose_bin_apq8039
    elif path.exists(firehose_bin_sda660):
        return firehose_bin_sda660
    else:
        return None
