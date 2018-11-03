#!/usr/bin/env python3

import os
import sys
import time
import logging
import signal

from boop import *

from boop.hopper import Hopper
from boop.sniffer import BoopSniff

from boop.helpers import packet
from boop.helpers.clients import Client
from boop.helpers.access_points import AccessPoint

logging.getLogger("boop.sniffer").setLevel(logging.WARNING)

app = BoopSniff("wlx18d6c70f910d", Hopper("wlx18d6c70f910d"))
app.packets = 0
app.hidden = []
app.access_points = {}
app.clients = {}

@app.handler(MGMT_DEAUTH)
def pkt(self, p):
    self.packets += 1
    # print("packet")
    return

@app.handler(MGMT_BEACON)
def pkt(self, p):
    self.packets += 1

    if self.access_points.get(p.addr2):

        self.access_points[p.addr2].mSig = (packet.get_rssi(p.notdecoded))
        self.access_points[p.addr2] + 1

    else:

        name = packet.get_ssid(p.info)

        if "< len: " in name:
            self.hidden.append(p.addr3)

        sec, cipher = packet.get_security(p)

        # Create AP object.
        self.access_points[p.addr2] = AccessPoint(
            name,
            ":".join(sec),
            cipher,
            packet.get_channel(p),
            p.addr3,
            packet.get_vendor(p.addr3),
            packet.get_rssi(p.notdecoded),
            p
        )

    return

@app.printer()
def printa(self):
    start = time.time()
    channel = 0

    while True:

        time_elapsed = int(time.time() - start)

        # Perform math to get elapsed time.
        hour = (time_elapsed // 3600)
        mins = (time_elapsed % 3600) // 60
        secs = (time_elapsed % 60)

        if hour > 0:
            ptime = "%d h %d m %d s" % (hour, mins, secs)
        elif mins > 0:
            ptime ="%d m %d s" % (mins, secs)
        else:
            ptime = "%d s" % secs

        try:
            channel = self.channel()
        except:
            pass

        os.system("clear")

        sys.stdout.write(f"[{self.packets}] T: [{ptime}] C: [{channel}]\n\n")

        sys.stdout.write(
            "{0}{1}{2}{3}{4}{5}{6}{7}\n".format(
                "Mac Addr".ljust(19, " "),
                "Enc".ljust(10, " "),
                "Cipher".ljust(12, " "),
                "Ch".ljust(5, " "),
                "Vendor".ljust(10, " "),
                "Sig".ljust(5, " "),
                "Bcns".ljust(8, " "),
                "SSID"
            )
        )

        for key in self.access_points:
            value = self.access_points[key]
            sys.stdout.write(
                " {0}{1}{2}{3:<5}{4}{5:<5}{6:<8}{7}\n".format(
                    value.mMAC.ljust(19, " "),
                    value.mEnc.ljust(10, " "),
                    value.mCipher.ljust(11, " "),
                    value.mCh,
                    value.mVen.ljust(10, " "),
                    value.mSig,
                    value.mBeacons,
                    value.mSSID
                )
            )

        sys.stdout.write(
            "\n{0}{1}{2}{3}{4}\n".format(
                "Mac".ljust(19, " "),
                "AP Mac".ljust(19, " "),
                "Noise".ljust(7, " "),
                "Sig".ljust(5, " "),
                "AP SSID"
            )
        )

        sys.stdout.flush()
        time.sleep(3)

def signal_handler(*args):
    time.sleep(2.5)
    print("\r[+] Commit to exit."+" "*25)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
app.run()
