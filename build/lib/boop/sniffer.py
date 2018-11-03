
import time
import logging

from boop import *

import pyric
import pyric.pyw as pyw

from functools import wraps

from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key

class BoopSniff:

    def __init__(self, interface : str, hopper = None, target : str = None):

        if interface not in WIRELESS_DEVICES:
            raise ValueError(f"Invalid interface: {interface}")

        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.ERROR,
            format='%(name)-12s:%(levelname)-8s | %(funcName)-12s:%(lineno)-4d | %(message)s')

        self.interface = pyw.getcard(interface)
        self.handler_map = {0:{}, 1:{}, 2:{}}

        self.filter = f"ether host {target}" if target else None
        self.hopper = hopper

        self.logger.info(f"App created on interface: {self.interface.dev}")

    def __str__(self):
        return f"BoopSniff({self.interface.dev})"

    def __repr__(self):
        return self.__str__()

    def handler(self, ptype):
        def __handle(f):
            self.handler_map[ptype[0]][ptype[1]] = f
            self.logger.info(f"Handler set for: {ptype[0]}:{ptype[1]}")
            return f
        return __handle

    def printer(self):
        def __printer(f):

            if not hasattr(self, 'pthread'):
                self.logger.info(f"Printer Thread Given")

                self.pthread = Thread(target=f, args=(self,))
                self.pthread.daemon = True
                self.pthread.start()
                return f

            return None
        return __printer

    def pkt_router(self, pkt):
        if pkt.subtype in self.handler_map[pkt.type].keys():
            self.handler_map[pkt.type][pkt.subtype](self, pkt)

    def run(self, f=None, timeout=None):
        if self.hopper:
            self.pthread = Thread(target=self.hopper.run)
            self.pthread.daemon = True
            self.pthread.start()

        sniff(
            iface=self.interface.dev, filter=self.filter,
            prn=f or self.pkt_router, timeout=timeout, store=0)

    def channel(self):
        return get_channel(self.interface)
