#!/usr/bin/env python3

import boop
import time

app = boop.BoopSniff(boop.WIRELESS_DEVICES[0])
app.packets = 0

@app.handler(boop.MGMT_DEAUTH)
def pkt(self, p):
    self.packets += 1
    return

@app.handler(boop.MGMT_BEACON)
def pkt(self, p):
    self.packets += 1
    return

@app.printer()
def printa(self):
    while True:
        print(self.packets)
        time.sleep(5)

app.run()
