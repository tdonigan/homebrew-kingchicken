#!/usr/bin/env python

import os
import errno
import sys
import qcomdl

if len(sys.argv) != 2:
    print "usage: %s outdir" % os.path.basename(sys.argv[0])
    sys.exit(1)

outdir = sys.argv[1]

edl = qcomdl.Edl()
assert edl.diag_connect(), "Cannot connect to EDL diagnostic device"

sahara = qcomdl.Sahara(edl)
try:
    assert sahara.enter_memory_debug(), "Cannot enter Sahara memory debug mode"

    try:
        os.makedirs(outdir)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(outdir):
            pass
        else:
            raise

    assert sahara.dump_memory_table(outdir), "Dumping the target's memory table failed"
finally:
    # attempt a device reset as our final step
    sahara.reset_device()
