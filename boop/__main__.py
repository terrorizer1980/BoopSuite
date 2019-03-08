#!/usr/bin/env python3

from .all import *

app = Sniffer("wlan0mon")
app.packets = 0

@app.handler(MGMT_BEACON)
def beacon(self, p):
    self.packets += 1
    print(p.bssid_vendor)
    return

@app.handler(MGMT_PROBE_RESP)
def probe_resp(self, p):
    self.packets += 1
    print(p)
    return

app.run()