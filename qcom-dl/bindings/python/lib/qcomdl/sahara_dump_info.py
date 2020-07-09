#!/usr/bin/env python

import qcomdl
for device in qcomdl.Edl.list_devices():
    edl = qcomdl.Edl()
    bus = device["bus"]
    port = device["port"]
    print "Dumping device info at bus=" + str(bus) + "/port=" + str(port)
    if edl.connect_bus_and_port(bus, port) == True:
        sahara = qcomdl.Sahara(edl)
        print "[+] Dumping device info"
        print sahara.device_info()
        print "[+] Dumping debug data"
        print {'debug_data': sahara.read_debug_data()}
        sahara.reset_device()
        edl.disconnect()
