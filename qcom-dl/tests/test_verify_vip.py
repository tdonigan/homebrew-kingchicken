import qcomdl
import distutils.dir_util


def test_qcomdl_verify_vip_edl_vip_device_flashables_dir(edl_vip_device_flashables_dir):
    assert qcomdl.verify_vip(edl_vip_device_flashables_dir) == True

def test_qcomdl_verify_vip_zero_flashables_dir(zero_flashables_dir):
    assert qcomdl.verify_vip(zero_flashables_dir) == True

def test_qcomdl_verify_fails_bad_file_data(zero_flashables_dir, tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp(__name__)
    distutils.dir_util.copy_tree(zero_flashables_dir, tmpdir.strpath)
    with open(tmpdir.join('zero1k.bin').strpath, 'rb+') as f:
        f.write("\x01")
    assert qcomdl.verify_vip(tmpdir.strpath) == False

def test_qcomdl_verify_fails_extra_xml_message(zero_flashables_dir, tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp(__name__)
    distutils.dir_util.copy_tree(zero_flashables_dir, tmpdir.strpath)
    xml_data = None
    with open(tmpdir.join('vip_commands.xml').strpath, 'rb') as f:
        xml_data = f.read()

    xml_data = xml_data.replace("</messages>", "<message>414141</message></messages>")
    with open(tmpdir.join('vip_commands.xml').strpath, 'wb') as f:
        xml_data = f.write(xml_data)
    assert qcomdl.verify_vip(tmpdir.strpath) == False

def test_qcomdl_verify_ignores_extra_xml_tag(zero_flashables_dir, tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp(__name__)
    distutils.dir_util.copy_tree(zero_flashables_dir, tmpdir.strpath)
    xml_data = None
    with open(tmpdir.join('vip_commands.xml').strpath, 'rb') as f:
        xml_data = f.read()

    xml_data = xml_data.replace("</messages>", "<notamessage>blah</notamessage></messages>")
    with open(tmpdir.join('vip_commands.xml').strpath, 'wb') as f:
        xml_data = f.write(xml_data)
    assert qcomdl.verify_vip(tmpdir.strpath) == True

def test_qcomdl_verify_fails_bad_xml(zero_flashables_dir, tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp(__name__)
    distutils.dir_util.copy_tree(zero_flashables_dir, tmpdir.strpath)
    with open(tmpdir.join('vip_commands.xml').strpath, 'ab') as f:
        f.write("garbage")
    assert qcomdl.verify_vip(tmpdir.strpath) == False

def test_qcomdl_verify_fails_bad_digest(edl_vip_device_flashables_dir, tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp(__name__)
    distutils.dir_util.copy_tree(edl_vip_device_flashables_dir, tmpdir.strpath)
    with open(tmpdir.join('chained_digests.bin').strpath, 'rb+') as f:
        f.write("\x01"*32)
    assert qcomdl.verify_vip(tmpdir.strpath) == False

def test_qcomdl_verify_fails_extra_nonnull_digest(edl_vip_device_flashables_dir, tmpdir_factory):
    tmpdir = tmpdir_factory.mktemp(__name__)
    distutils.dir_util.copy_tree(edl_vip_device_flashables_dir, tmpdir.strpath)
    with open(tmpdir.join('chained_digests.bin').strpath, 'ab') as f:
        f.write("\x01"*32)
    assert qcomdl.verify_vip(tmpdir.strpath) == False

