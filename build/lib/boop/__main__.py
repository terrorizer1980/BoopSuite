#!/usr/bin/env python3

import time
import logging

from boop import *

from boop.hopper import Hopper
from boop.sniffer import BoopSniff

logging.getLogger("boop.sniffer").setLevel(logging.WARNING)

app = BoopSniff("wlx18d6c70f910d", Hopper("wlx18d6c70f910d"))
app.packets = 0

@app.handler(MGMT_DEAUTH)
def pkt(self, p):
    self.packets += 1
    return

@app.handler(MGMT_BEACON)
def pkt(self, p):
    self.packets += 1
    return

@app.printer()
def printa(self):
    while True:
        print(self.packets)
        time.sleep(5)

app.run()
