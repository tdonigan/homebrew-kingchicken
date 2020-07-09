#!/usr/bin/env python

# Using this script for production image flashing is not recommended!
# This script is for demonstration/testing purposes only

from sys import argv, exit
from time import sleep
import os

if len(argv) < 2:
    print "usage: %s <images_dir>" % argv[0]
    exit(1)

import qcomdl

images_dir = argv[1]
firehose_bin = os.path.join(images_dir, "validated_emmc_firehose_8936.mbn")

qcomdl.set_loglevel(999) # be really verbose
edl = qcomdl.Edl()
if edl.connect() == True:
    sahara = qcomdl.Sahara(edl)

    print "Uploading firehose"
    if sahara.upload(firehose_bin) == True and sahara.done() == True:
        print "sleeping 3 seconds while we await firehose to come up"
        sleep(3)

        firehose = qcomdl.Firehose(edl)
        firehose.run_vip(images_dir, "vip_commands.xml", "signed_digest_table.mbn", "chained_digests.bin")

    edl.disconnect()
