#!/usr/bin/env python

from xml.etree import ElementTree
from optparse import OptionParser
import qcomdl
import time
import sys
import os

DEFAULT_PARTITION_NUMBER = "0"

def get_args(argv=sys.argv):
    usage = "usage: %s [options] <path/to/images-dir or path/to/image-file>" % os.path.basename(argv[0])
    o = OptionParser(usage=usage)
    o.add_option('-L', '--label',
            default=[],
            help='Flash only specified labels in program xml. Repeat for multiple labels. Ignored when path argument is a file.',
            dest='labels',
            action='append')
    o.add_option('-F', '--filename',
            default=[],
            help='Flash only specified files in program xml. Repeat for multiple files. Ignored when path argument is a file.',
            dest='filenames',
            action='append')
    o.add_option('-f', '--firehose-bin',
            default=qcomdl.FIREHOSE_DEFAULT_BIN_APQ8039,
            help=('Specify an alternate firehose file than %s' % qcomdl.FIREHOSE_DEFAULT_BIN_APQ8039),
            dest='firehose_bin',
            action='store')
    o.add_option('-p', '--program-xml',
            default=qcomdl.FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME,
            help=('Specify an alternate program file than %s' % qcomdl.FIREHOSE_DEFAULT_PROGRAM_XML_FILENAME),
            dest='program_xml',
            action='store')
    o.add_option('-P', '--patch-xml',
            default=qcomdl.FIREHOSE_DEFAULT_PATCH_XML_FILENAME,
            help=('Specify an alternate patch file than %s' % qcomdl.FIREHOSE_DEFAULT_PATCH_XML_FILENAME),
            dest='patch_xml',
            action='store')
    o.add_option('-S', '--start-sector',
            default=None,
            help=('Specify the start-sector to write a single file to. Ignored when path argument is a directory. '+
                  'This is looked up in the raw_program.xml file by default. ' +
                  'This argument is useful mostly to override rawprogram.xml or to flash a file that is not listed. '),
            dest='single_start_sector',
            action='store')
    o.add_option('-N', '--partition-number',
            default=DEFAULT_PARTITION_NUMBER,
            help=('Specify the partition-number to write a single file to. Only used in conjunction with -S/--start-sector. '+
                  'This is looked up in the raw_program.xml file by default. ' +
                  'This argument is useful mostly to override rawprogram.xml or to flash a file that is not listed. ' + 
                  ("Default: %s" % DEFAULT_PARTITION_NUMBER)),
            dest='single_partition_number',
            action='store')
    o.add_option('-e', '--erase',
            default=False,
            help='Erase all of mmc before flashing',
            dest='do_erase',
            action='store_true')
    o.add_option('--dry-run',
            default=False,
            help='Dry run using SkipWrite=1 on program.xml (patch xml skipped)',
            dest='dry_run',
            action='store_true')
    o.add_option('--no-patch',
            default=True,
            help='Do not apply patches',
            dest='do_patch',
            action='store_false')
    o.add_option('--no-sahara_info',
            default=True,
            help='Do not query the device for sahara info',
            dest='do_sahara_info',
            action='store_false')

    (options, args) = o.parse_args(argv)

    if(options.dry_run and options.do_erase):
        print "Error: options --dry-run and --erase may not be used together"
        return (None, None)

    if len(args) != 2:
        print usage
        return (None, None)

    image_path = args[1]

    options.single_file = None
    if os.path.isdir(image_path):
        image_dir = image_path
    elif os.path.isfile(image_path):
        image_dir = os.path.dirname(image_path)
        options.single_file = os.path.basename(image_path)
    else:
        print("Error: Inaccessible or nonexistent file/dir argument: %s" % image_path)
        return (None, None)

    return (options, image_dir)


def filtered_programs(program_xml_path, labels, filenames):
    programs = map((lambda pg: pg.attrib), ElementTree.parse(program_xml_path).iter('program'))
    programs2 = []
    for pg in programs:
        if pg['filename']:
            programs2.append(pg)

    if (not labels) and (not filenames):
        return programs2

    programs3 = []
    for pg in programs2:
        if (labels and pg["label"] in labels) or (filenames and pg["filename"] in filenames):
            programs3.append(pg)
    return programs3


def main(argv=sys.argv):
    options, image_dir = get_args(argv)
    if not options or not image_dir:
        return False

    firehose_bin_path = os.path.join(image_dir, options.firehose_bin)
    program_xml_path = os.path.join(image_dir, options.program_xml)
    patch_xml_path = os.path.join(image_dir, options.patch_xml)

    for path in [firehose_bin_path, program_xml_path, patch_xml_path]:
        if not os.path.exists(path):
            print "Error: missing file: %s" % path
            return False

    if options.single_file:
        if options.single_start_sector:
            programs = [{
                            "start_sector" : options.single_start_sector,
                            "physical_partition_number" : options.single_partition_number,
                            "filename" : options.single_file,
                       }]

        else:
            programs = filtered_programs(program_xml_path, None, [options.single_file])
            if not programs:
                print("No programs file entry found for file: %s" % options.single_file)
                return False
    else:
        programs = filtered_programs(program_xml_path, options.labels, options.filenames)
        if not programs:
            print("No programs file entries found")
            return False

    if (options.labels or options.filenames) and not programs:
        print "Error: filtering labls/filenames returned an empty list of program files"
        return False

    edl = qcomdl.Edl()
    print "Connecting to EDL"
    if not edl.connect():
       return False

    try:
        sahara = qcomdl.Sahara(edl)

        if options.do_sahara_info:
            print "Dumping device info"
            print sahara.device_info()
            print "[+] Dumping debug data"
            print {'debug_data': sahara.read_debug_data()}

        print "Uploading firehose"
        if not sahara.upload(firehose_bin_path) == True or not sahara.done():
            return False

        print "Sleeping 3 seconds while firehose comes up"
        time.sleep(3)

        firehose = qcomdl.Firehose(edl)
        try:
            if options.dry_run:
                assert not options.do_erase
                firehose.cfg_set_skip_write(1)

            if not firehose.configure():
                return False

            print "Configured with MemoryName=%s TargetName=%s" %(firehose.memory_name(), firehose.target_name())

            if options.do_erase:
                firehose.erase(0)

            for pg in programs:
                full_path = os.path.join(image_dir, pg['filename'])
                ss = pg['start_sector']
                ppn = pg['physical_partition_number']
                print "Flashing %s at start-sector: %s - partition: %s" %(full_path, ss, ppn)
                firehose.program(full_path, ss, ppn, 0)

            # TODO filter patch statements? for now we can just opt out of patching altogether
            if not options.dry_run and options.do_patch and not firehose.patch_from_file(patch_xml_path):
                return False

        finally:
            firehose.soft_reset(0)
        return True
    finally:
        edl.disconnect()


if __name__ == "__main__":
    if main(): ret = 0
    else: ret = 1
    sys.exit(ret)
