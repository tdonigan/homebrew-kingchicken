import pytest
import shutil

import qcomdl

## Helper

def sanitize_filename(fname):
    return fname.replace("/", "_").replace("\\", "_")


## Fixtures

@pytest.fixture(scope='function')
def sahara_diag(request, squid_device):
    assert squid_device.bootIntoDiagEDL()
    edl = qcomdl.Edl()
    assert edl.diag_connect()
    def _disconnect_edl():
        if edl.isconnected():
            edl.disconnect()
    request.addfinalizer(_disconnect_edl)
    sahara = qcomdl.Sahara(edl)
    assert sahara.enter_memory_debug()
    return sahara


## Tests

def test_has_memory_table(sahara_diag):
    table = sahara_diag.parse_memory_table()
    assert table is not None
    assert len(table) == 11
    filenames = [ent["filename"] for ent in table]
    expected_filenames = [
        'OCIMEM.BIN',
        'CODERAM.BIN',
        'DATARAM.BIN',
        'MSGRAM.BIN',
        'PMIC_PON.BIN',
        'RST_STAT.BIN',
        'PMIC_RTC.BIN',
        'DDR_DATA.BIN',
        'DDRCS0.BIN',
        'DDRCS1.BIN',
        'load.cmm',
    ]
    assert filenames == expected_filenames


def test_memory_read(sahara_diag):
    table = sahara_diag.parse_memory_table()
    assert len(table) == 11
    for ent in table:
        readsize = min(ent["length"], 0x1000)  # just read a small chunk from each file, some are larger than the max
        raw = sahara_diag.memory_read(ent["address"], readsize)
        assert len(raw) == readsize


def test_memory_read_to_file(sahara_diag, tmpdir, request):
    subdir = tmpdir.mkdir("memory_read_to_file")
    request.addfinalizer(lambda: shutil.rmtree(str(subdir)))
    table = sahara_diag.parse_memory_table()
    assert len(table) == 11
    for ent in table:
        outf = subdir.join(sanitize_filename(ent["filename"]))
        assert sahara_diag.memory_read_to_file(ent["address"], ent["length"], str(outf))
        assert outf.size() == ent["length"]


def test_memory_dump_table(sahara_diag, tmpdir, request):
    subdir = tmpdir.mkdir("memory_table_dump")
    request.addfinalizer(lambda: shutil.rmtree(str(subdir)))
    assert sahara_diag.dump_memory_table(str(subdir))
    table = sahara_diag.parse_memory_table()
    assert len(table) == 11
    for ent in table:
        outf = subdir.join(sanitize_filename(ent["filename"]))
        assert outf.size() == ent["length"]

