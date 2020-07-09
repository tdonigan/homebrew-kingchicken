from glob import glob
from setuptools import setup, Extension
import os

with open("VERSION", 'r') as f:
    VERSION = f.readline().rstrip("\n")

srcs = glob('src/*.c') + glob('bindings/python/*.c')
srcs.remove('src/main.c')

cflags = [
    "-Werror",
    "-Wall",
    "-Wno-unknown-pragmas",
    "-Wno-unknown-warning-option",
    "-std=gnu99",
    ("-DQCOMDL_VERSION=\"%s\"" % VERSION),
]

# default to a debug build but without -DDEBUG (for now)
if os.environ.has_key("DEBUG_CFLAGS"):
    cflags.append(os.environ["DEBUG_CFLAGS"])
else:
    cflags.append("-g")

setup (name = 'qcomdl',
        version = VERSION,
        description = 'qcomdl is for flashing firmware on qualcomm devices',
        packages = [ 'qcomdl' ],
        package_dir = {'' : 'bindings/python/lib'},
        entry_points = {
            "console_scripts": [
                "qdl = qcomdl.qdl:main",
            ],
        },
        ext_modules = [
            Extension('qcomdl._qcomdl_native',
                sources = srcs,
                include_dirs = [
                    'inc',
                    '/usr/include/libxml2',
                    '/usr/local/include/libxml2',
                    '/usr/include/libusb-1.0',
                    '/usr/local/include/libusb-1.0',
                ],
                library_dirs = ['/usr/local/lib'],
                libraries = ['usb-1.0', 'xml2', 'zip', 'yaml'],
                extra_compile_args = cflags,
            )
        ]
    )
