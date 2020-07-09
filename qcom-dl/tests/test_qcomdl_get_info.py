import qcomdl


## Tests

# NOTE:
# unfortunately we can't really achieve good test conditions with bran running
# Android here since we do not have control over being able to load and
# control a working a bran android image in these unit tests. A better place
# for that test is in x2-test as a test with each bran build.

def test_qcomdl_get_device_info_in_edl(squid_device):
    squid_device.bootIntoEDL()
    ret = qcomdl.get_device_info()
    assert ret
    assert isinstance(ret, dict)

def test_qcomdl_get_device_info_missing_device(squid_device):
    squid_device.powerOff()
    ret = qcomdl.get_device_info()
    assert ret == None

