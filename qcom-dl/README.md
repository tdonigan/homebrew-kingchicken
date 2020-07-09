# qcom-dl

Library and tools for flashing devices over Qualcomm's proprietary EDL
(Emergency Down Load) interface. Supports the Sahara and Firehose
protocols.

## Installing prebuilts

### Installing a prebuilt executable via Homebrew (OS X only)

There is a qcom-dl homebrew recipe available for OS X. If you have
topsoiled your environment using `compost` you can simply run:

    brew update
    brew install square/formula/qcom-dl

If you haven't run topsoil on your system, you can add the square homebrew formulas and
install qcom-dl as follows:

    brew tap square/formula ssh://git@git.sqcorp.co/sq/homebrew-formulas.git
    brew update
    brew install square/formula/qcom-dl

Note that this does not include the `qcomdl` Python bindings.

### Installing a prebuilt Python wheel via pip

The Python bindings can be installed via

    pip install qcomdl

It is recommended to install into a virtualenv rather than globally on your system.

Note that this does not include the `qcom-dl` executable.

## Building from source

The makefile is self-documenting. You can see a list of tasks by
running:

    make help

All build artifacts are put in the `build/` subdirectory.

To build the native code (qcom-dl executable, libqcom shared object, and
static library):

    make all

To build and install the python bindings under a python virtual
environment:

    make setup

The python virtual environment will be located at `build/venv/`.  You
can "activate" it in your shell environment by running:

   source build/venv/bin/activate

Later you can use the `deactivate` shell alias to return to your
previous environment settings.

### Requirements

* libusb-1.0
* libxml2
* libzip
* libyaml
* clang (for building on linux/darwin)
* pkg-config (for building on linux/darwin)
* python 2.7 (for python bindings)
* python virtualenv (for building python bindings)
* mingw (for cross-compiling the windows package)

If you need libusb debugging for diagnostic purposes, make sure you use
libusb 1.0.21 or earlier or build libusb 1.0.22 or later with debugging
enabled.

#### Ubuntu-specific list of packages to install

Run the following:

    sudo apt-get update
    sudo apt-get install libusb-1.0 libxml2-dev libzip libyaml-dev pkg-config python-pip python-virtualenv python-dev build-essential clang ruby

#### OS X-specific list of packages to install

Run the following:

    brew install libusb-1.0 pkg-config libzip libyaml
    pip install virtualenv

## Building the Windows package

MINGW is used to build for windows. On Ubuntu, the standard Ubuntu 'mingw-64'
package should be installed.

    sudo apt install mingw-64

If you are building on a Mac, you should install the mingw-w64 homebrew package.

    brew install mingw-w64

Once everything is ready, just run:

    make windows_package

Note: This will automatically download several prerequisite
[Windows DLLs and C headers from hwbuild](https://hwbuild.corp.squareup.com/x2/build-prereqs/windows).
You can find the list of libraries in `windows-packages.txt`.

When adding new Windows libraries, [Fedora's
Packages project](https://apps.fedoraproject.org/packages/s/mingw32-) can be
useful for finding pre-built mingw32 packages. Many of the existing
Windows prebuilts come from their 'Rawhide' release.
Here's an example page for
[bzip2](https://apps.fedoraproject.org/packages/mingw-bzip2/builds/)

There is a script named `mingw-rpm-to-zip` that will convert an `rpm` to a `zip`
file by copying header and DLL files from the `rpm`.

NOTE: `gcc-libs` is a special case due to libzip requiring `__udivdi3` function.

To produce it: `tools/mingw-rpm-to-zip
mingw32-gcc-8.1.0-2.fc29.x86_64.rpm
gcc-libs-8.1.0-2.zip`

If everything builds, the resulting windows package will be located at `build.win/qcomdl.win32.zip`

## Usage

In normal usage the `qcom-dl` executable takes a single argument; the path
to the image directory or a zip file.

There exist various optional arguments that can be specified for
diagnostic, troubleshooting, and/or testing purposes. You can see the
full list with `qcom-dl -h/--help`

## Testing

To run a limited set of basic tests just to verify the module loads and
supports basic functions without any EDL devices attached, run the
following:

    make test_basic


To run the full suite of tests, you will need a device connected in EDL
mode. Run the following:

    make test

## Building and releasing the Python wheel

Before making a release, bump the version in `VERSION` and tag the version (`make tag_version`).
Make sure not to upload a wheel from a commit that's not on a version tag, as our build system has no concept of snapshot versions.

Use the `qcom-dl` [rackdash job](https://rackdash.sqprod.co/ui/build_jobs/new) to generate and upload the updated python wheels for macos and linux.

This can also be done manually using twine.

See [go/dsepython](https://wiki.sqcorp.co/display/HAR/DSE+Python) for instructions on how to build and release a wheel with twine. After installing and setting up twine, run the following:

    rm dist/qcomdl-*.whl
    python setup.py bdist_wheel
    twine upload -r squarepypi dist/qcomdl-*.whl

Note that the Python package is called `qcomdl`, not `qcom-dl`.

IMPORTANT: because `qcomdl` contains native code, *you must build and release a wheel for all of our supported operating systems*:
* Ubuntu 16.04 (x86-64)
* Mac OS X 10.12+ (x86-64)

You will need access to a machine running the target operating system in order to build the wheel for that operating system.

For Ubuntu 16.04, please see an APT member for access to a SQUID build node.

For OS X 10.12+, please see an ESW member for access to a Riker build node. *Do not build and upload the wheel from your Macbook running 10.13 or later, as it will be incompatible with 10.12 and break ESW builds.*

## Releasing the updated brew formula

Modify the `qcom-dl.rb` forumula in [homebrew formulas](https://git.sqcorp.co/projects/SQ/repos/homebrew-formulas/browse) by pointing the tag to the new version.