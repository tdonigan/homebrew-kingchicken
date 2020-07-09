#!/usr/bin/env python

from sys import argv, exit
from time import sleep

if len(argv) < 2:
    print "usage: " + argv[0] + " <firehose_bin.mbn>"
    exit(1)

import qcomdl

firehose_bin = argv[1]

edl = qcomdl.Edl()
if edl.connect() == True:
    sahara = qcomdl.Sahara(edl)

    print "Uploading firehose"
    if sahara.upload(firehose_bin) == True and sahara.done() == True:
        print "sleeping 3 seconds while we await firehose to come up"
        sleep(3)

        firehose = qcomdl.Firehose(edl)
        if firehose.configure() == True:
            firehose.ping()
            firehose.erase(0)
        firehose.soft_reset(0)

    edl.disconnect()
