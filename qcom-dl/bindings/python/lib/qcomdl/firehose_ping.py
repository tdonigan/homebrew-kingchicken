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
            print "Configured with target: MemoryName=" + firehose.memory_name() + " TargetName=" + firehose.target_name()
            for i in range(10):
                print "Sending ping #" + str(i+1)
                firehose.ping()
                sleep(0.5)

            print "Ping test finished"

        firehose.soft_reset(0)

    edl.disconnect()
