#!/usr/bin/env python3
#-*- coding: utf-8 -*-

import os
import sys
import signal

from loguru import logger
from functools import wraps
from scapy.all import *

from .oui import OUI
from .constants import *
from .d11_frame import Dot11Frame

class BadInterface(Exception):

    def __init__(self, message):
        super().__init__(message)

class Sniffer:

    def __init__(self, interface : str, target : str = "", filter : str = ""):

        if not ROOT:
            import pwd
            raise OSError(f"User {pwd.getpwuid(os.getuid())[0]} is not root")

        if interface not in MWINTERFACES:
            if interface in INTERFACES:
                raise BadInterface(f"Interface {interface} exists but is not in the correct mode")
            else:
                raise BadInterface(f"{interface} is not a valid interface.")

        self.interface = interface
        self.handler_map = {0:{}, 1:{}, 2:{}}
        self.filter = f"ether host {target}" if target else None

        if __debug__: 
            logger.info(f"Sniffer Created on {interface}")

    def __str__(self) -> str:
        return f"Sniffer({self.interface})"

    def __repr__(self) -> str:
        return self.__str__()

    def handler(self, packet_type):
        @wraps(packet_type)
        def __handle(func):
            self.handler_map[packet_type[0]][packet_type[1]] = func
            if __debug__: 
                logger.info(f"Handler set for: {packet_type[0]}:{packet_type[1]}")
            return func
        return __handle

    def router(self, pkt):
        try:
            self.handler_map[pkt.type][pkt.subtype](self, Dot11Frame(pkt))
        except KeyError:
            pass
        return 

    def run(self):
        sniff(
            iface=self.interface, filter=self.filter,
            prn=self.router, store=0
        )

def signal_handler(sig, frame):
    print("\r[+] SIGINT RECIEVED...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
