.SUFFIXES: .c .o

include version.mk

CC := clang
CXX := clang

# platform specific stuff
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
DLL_EXT := dylib
DLL_LDFLAGS := -dynamiclib
endif

ifeq ($(UNAME_S),Linux)
DLL_EXT := so
DLL_LDFLAGS := -shared
endif

HEADER_SEARCH_CFLAGS := -I./inc \
                        -DQCOMDL_VERSION=\"$(VERSION)\" \
                        $(shell pkg-config --cflags-only-I libxml-2.0) \
                        $(shell pkg-config --cflags-only-I libusb-1.0) \
                        $(shell pkg-config --cflags-only-I libzip) \
                        $(shell pkg-config --cflags-only-I yaml-0.1) \

SOURCEDIR := src
BUILDDIR := build

EXE_PRODUCT := $(BUILDDIR)/qcom-dl
LIB_PRODUCT := $(BUILDDIR)/libqcomdl.$(DLL_EXT)
STATIC_LIB_PRODUCT := $(BUILDDIR)/libqcomdl.a

PY_VENV_DIR := $(BUILDDIR)/venv

PIP := $(PY_VENV_DIR)/bin/python -m pip
PYTEST := $(PY_VENV_DIR)/bin/python -m pytest
VIRTUALENV := /usr/bin/env python2 -m virtualenv

SRCS := $(wildcard $(SOURCEDIR)/*.c)
LIB_SRCS := $(filter-out $(SOURCEDIR)/main.c, $(SRCS))

WARNINGS := error all everything
NO_WARNINGS := packed \
               padded \
               gnu-folding-constant \
               gnu-zero-variadic-macro-arguments \
               shift-sign-overflow \
               documentation-unknown-command \
               reserved-id-macro \
               variadic-macros \
               unused-parameter \
               documentation \
               disabled-macro-expansion \
               unknown-warning-option \
               vla \

## enable DEBUG compile-time flag to get function names and other extra-verbose logging info
#DEBUG_CFLAGS ?= -g -DDEBUG
DEBUG_CFLAGS ?= -g

CFLAGS += -O2 \
		  -fvisibility=hidden \
		  -fPIC \
		  $(patsubst %,-W%,$(WARNINGS)) \
		  $(patsubst %,-Wno-%,$(NO_WARNINGS)) \
		  $(HEADER_SEARCH_CFLAGS) \
		  $(DEBUG_CFLAGS)

LDFLAGS := $(shell pkg-config --libs libxml-2.0) \
           $(shell pkg-config --libs libusb-1.0) \
           $(shell pkg-config --libs libzip) \
           $(shell pkg-config --libs yaml-0.1) \

TEST_FIREHOSE_BIN := "bran_data/Bran 2015-12-03/prog_emmc_firehose_8936.mbn"
TEST_PROGRAM_XML :=  "bran_data/Bran 2015-12-03/rawprogram_unsparse.xml"
TEST_PATCH_XML := "bran_data/Bran 2015-12-03/patch0.xml"

WINDOWS_MK := Makefile.win

# make our OBJ lists from SRCS lists
OBJS := $(patsubst $(SOURCEDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
LIB_OBJS := $(patsubst $(SOURCEDIR)/%.c,$(BUILDDIR)/%.o,$(LIB_SRCS))

# targets

help: # default task

all: exe lib staticlib ##@Build Build all the native products (lib, exe, staticlib)

exe: $(EXE_PRODUCT) ##@Build Build the main executable

lib: $(LIB_PRODUCT) ##@Build Build the dynamic library

staticlib: $(STATIC_LIB_PRODUCT) ##@Build Build the static library

windows_exe: ##@Build Build the windows executable
	make -f $(WINDOWS_MK) exe

windows_package: ##@Build Build the windows zipball with the exe and its dependencies
	make -f $(WINDOWS_MK) package

$(PY_VENV_DIR):
	$(VIRTUALENV) --no-site-packages $(PY_VENV_DIR)
	ln -fs $(PY_VENV_DIR)/bin/activate pyenv

setup: $(PY_VENV_DIR) ##@Setup Set up the python environment
	$(PIP) install --upgrade .

windows_deps: ##@Setup Install windows build dependencies
	make -f $(WINDOWS_MK) deps

test: test_requirements    ##@Test Run the basic and EDL device tests (minus EDL diagnostic mode tests)
	$(PYTEST) -s --junit-xml=build/test-report.xml \
		tests/test_basic.py \
		tests/test_verify_vip.py \
		tests/test_edl_device.py \
		tests/test_qcomdl_get_info.py \
		tests/test_edl_vip_device.py

test_basic: test_requirements  ##@Test Run the basic test-suite only (for non-DUT testing)
	$(PYTEST) -s --junit-xml=build/test-report.xml tests/test_basic.py tests/test_verify_vip.py

test_diag: test_requirements  ##@Test Run the edl diag mode test-suite only
	$(PYTEST) -s --junit-xml=build/test-report.xml tests/test_edl_diag_device.py

clean: windows_clean ##@Cleaning Clean build artifacts
	rm -f $(OBJS) $(EXE_PRODUCT) $(LIB_PRODUCT) $(STATIC_LIB_PRODUCT)

distclean: windows_distclean ##@Cleaning Destroy the build directory
	rm -rf $(BUILDDIR)

windows_clean: ##@Cleaning Clean build artifacts
	make -f $(WINDOWS_MK) clean

windows_distclean: ##@Cleaning Destroy the windows build directory
	make -f $(WINDOWS_MK) distclean


HELP_RUBY = help=Hash.new{|h,k|h[k]={}};\
            ARGV.each{|mf|File.read(mf).scan(/^(\w+)\s*:.*\#\#(?:@(\w+))?\s(.*)$$/){help[$$2||"options"][$$1]=$$3}};\
            help.each{|s,h|puts(s);h.each{|k,v|printf("  %s %s\n" %[k.ljust(16),v])};puts}

tag_version: VERSION ##@Miscellaneous Tag the git HEAD with the current VERSION and push tags
	@echo "*** Cowardly refusing to run the following \(do it manually\):"
	@echo
	@echo "  git tag v$(VERSION)"
	@echo "  git push --tags"
	@echo

help: ##@Miscellaneous Show this help
	@echo "Usage: make [target ...]\n"
	@ruby -e '$(HELP_RUBY)' $(MAKEFILE_LIST)


# "private" targets

test_requirements: setup
	$(PIP) install -r test_requirements.txt

exe_test: $(EXE_PRODUCT)
	@$(EXE_PRODUCT) $(TEST_FIREHOSE_BIN) $(TEST_PROGRAM_XML) $(TEST_PATCH_XML)

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.o: $(SOURCEDIR)/%.c
	$(CC) -c $(CFLAGS) $< -o $@

$(EXE_PRODUCT): $(BUILDDIR) $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

$(LIB_PRODUCT): $(LIB_OBJS)
	$(CC) -o $@ $(LIB_OBJS) $(LDFLAGS) $(DLL_LDFLAGS)

$(STATIC_LIB_PRODUCT): $(LIB_OBJS)
	ar rcs $@ $(LIB_OBJS)
	ranlib $@

rackdash_publish_wheel: ##@Publish Build and upload a wheel to Square's PyPI server. This target should only be run on Rackdash.
	python setup.py bdist_wheel
	pip install twine
	python -m twine upload --repository-url https://nexus3.sqcorp.co/repository/pypi-square-devicesoftware/ --username $(HW_BOT_PYPI_USERNAME) --password $(HW_BOT_PYPI_PASSWORD) dist/*.whl
