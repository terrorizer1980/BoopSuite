
import time
import logging

from random import choice

from boop import *

import pyric
import pyric.pyw as pyw

from pyric.lib import libnl as nl

class Hopper:

    def __init__(
        self,
        interface : str,
        frequencies : list = [2],
        channels : list = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]+FIVEHERTZ
    ):

        if interface not in WIRELESS_DEVICES:
            raise ValueError(f"Invalid interface: {interface}")

        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.ERROR,
            format='%(name)-12s:%(levelname)-8s | %(funcName)-12s:%(lineno)-4d | %(message)s')

        self.interface = pyw.getcard(interface)
        self.channels  = []

        if 2 in frequencies:
            [self.channels.append(x) for x in channels if x in range(12)]

        if 5 in frequencies:
            [self.channels.append(x) for x in channels if x in FIVEHERTZ]

    def __str__(self):
        return f"Hopper({self.channels})"

    def __repr__(self):
        return self.__str__()

    def __call__(self):
        self.run()

    def channel(self, chan=None):
        if chan:
            try:
                pyw.chset(self.interface, chan, self.nlsock)
            except:
                self.logger.warn(f"Failed to change channel: {self.interface.dev}: {chan}")
                return False
            return True
        return get_channel(self.interface)

    def run(self):
        while True:
            channel = choice(self.channels)

            try:
                pyw.chset(self.interface, channel, None)

            except:
                self.logger.warn(f"Failed to change channel: {self.interface.dev}: {channel}")

            time.sleep(5)
