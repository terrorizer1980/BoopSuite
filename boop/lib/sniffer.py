#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import pwd
import sys
# import curses
import random
import signal

from loguru import logger
from functools import wraps
from scapy.all import *

import pyric.pyw as pyw

from boop.lib import *
from boop.lib.types import *
from boop.lib.channels import *
from boop.lib.network import Network
from boop.lib.d11_frame import Dot11Frame


class BadInterface(Exception):
    def __init__(self, message):
        super().__init__(message)


class Sniffer:
    def __init__(self, interface: str, channel, target=None, verbose=1):

        if not verbose:
            logger.disable("boop.lib.sniffer")

        if not ROOT:
            raise OSError(f"User {pwd.getpwuid(os.getuid())[0]} is not root")

        if interface not in MWINTERFACES:
            if interface in INTERFACES:
                raise BadInterface(
                    f"Interface {interface} exists but is not in the correct mode"
                )
            else:
                raise BadInterface(f"{interface} is not a valid interface.")

        self.interface = interface
        self.channel = channel
        self.handler_map = {
            0: {
                0: [self.ASSOC_REQ], 
                1: [self.ASSOC_RESP],
                2: [self.REASSOC_REQ],
                3: [self.REASSOC_RESP],
                4: [self.PROBE_REQ],
                5: [self.PROBE_RESP],
                8: [self.BEACON],
                9: [self.ATIM],
                10: [self.DISASSOC],
                11: [self.AUTH],
                12: [self.DEAUTH]   # 13: ACTION, 14: NO_ACTION
                }, 
            1: {
                # 7: CTRL, 8: BLOCK_ACK_REQUEST, 9: BLOCK_ACK
                10: [self.POLL],
                11: [self.RTS],
                12: [self.CTS],
                13: [self.ACK],
                14: [self.CFEND],
                15: [self.CFECFA]
            }, 
            2: {
                0: [self.DATA_PARSER], 
                1: [self.DATA_PARSER],
                2: [self.DATA_PARSER],
                3: [self.DATA_PARSER],
                4: [self.DATA_PARSER],
                5: [self.DATA_PARSER],
                6: [self.DATA_PARSER],
                7: [self.DATA_PARSER],
                8: [self.DATA_PARSER],
                9: [self.DATA_PARSER],
                10: [self.DATA_PARSER],
                11: [self.DATA_PARSER],
                12: [self.DATA_PARSER],
            }}
        self.printer = printer
        self.filter = f"ether host {target}" if target else None
        self.sniffer_map = {"AP": {}, "CL": {}, "UCL": {}}
        self.hidden = []
        self.packets = 0

        if __debug__:
            logger.info(f"Sniffer Created on {interface}")

    def __str__(self) -> str:
        return f"Sniffer({self.interface})"

    def __repr__(self) -> str:
        return self.__str__()

    def handler(self, packet_type):
        @wraps(packet_type)
        def __handle(func):
            self.handler_map[packet_type[0]][packet_type[1]].append(func)
            if __debug__:
                logger.info(
                    f"Handler set for: {packet_type[0]}:{packet_type[1]}"
                )
            return func

        return __handle

    def router(self, pkt):
        self.packets += 1
        try:
            self.df = Dot11Frame(pkt)
            funcs = [x for x in self.handler_map[pkt.type][pkt.subtype]]
            funcs[0](self.df)
            for func in funcs[1:]:
                func(self, self.df)
        except KeyError:
            pass
            
        return 

    def run(self):
        if not self.channel:
            hop_thread = Thread(target=self.hopper)
            hop_thread.daemon = True
            hop_thread.start()
        else:
            interface = pyw.getcard(self.interface)
            set_channel(interface, int(self.channel))

        printer_thread = Thread(target=self.printer, args=(self,))
        printer_thread.daemon = True
        printer_thread.start()

        sniff(
            iface=self.interface, filter=self.filter, prn=self.router, store=0
        )

    def hopper(self):
        interface = pyw.getcard(self.interface)
        while True:
            channel = random.choice(TWOHERTZ)
            # print("channel", channel)
            set_channel(interface, channel)
            self.channel = channel
            time.sleep(4.5)

    def ap(self, mac):
        # print(self.sniffer_map["AP"].get(mac, None))
        return self.sniffer_map["AP"].get(mac, None)

    def client(self, mac):
        # print(self.sniffer_map["CL"].get(mac, None))
        return self.sniffer_map["CL"].get(mac, None)

    def ASSOC_REQ(self, dframe): pass

    
    def ASSOC_RESP(self, dframe): pass

    
    def REASSOC_REQ(self, dframe): pass

    
    def REASSOC_RESP(self, dframe): pass

    
    def PROBE_REQ(self, dframe): pass

    
    def PROBE_RESP(self, dframe): pass

    
    def BEACON(self, dframe):
        dframe.network_stats()
        if self.ap(dframe.src):
            self.sniffer_map["AP"][dframe.src].signal = dframe.signal
            self.sniffer_map["AP"][dframe.src] + 1
        else:
            # print(dframe.ssid)
            self.sniffer_map["AP"][dframe.src] = Network(
                dframe.ssid,
                dframe.security,
                dframe.cipher,
                dframe.channel,
                dframe.src,
                dframe.src_vendor,
                dframe.signal,
                dframe
            )

    
    def ATIM(self, dframe): pass

    
    def DISASSOC(self, dframe): pass

    
    def AUTH(self, dframe): pass

    
    def DEAUTH(self, dframe): pass

    
    def POLL(self, dframe): pass

    
    def RTS(self, dframe): pass

    
    def CTS(self, dframe): pass

    
    def ACK(self, dframe): pass

    
    def CFEND(self, dframe): pass

    
    def CFECFA(self, dframe): pass

    
    def DATA_PARSER(self, dframe): pass


def set_channel(card, channel, sock=None):
    while True:
        try:
            pyw.chset(card, channel, None, nlsock=sock)
            return
        except Exception as e:
            logger.error(e)
        time.sleep(1)

def printer(self):
    while True:
        print(self.packets)
        for network in self.sniffer_map["AP"].values():
            # print(network.mSSID, type(network.mSSID))         
            sys.stdout.write( 
                " {0}{1}{2}{3:<5}{4}{5:<5}{6:<8}{7}\n".format(
                    network.mMAC.ljust(19, " "),
                    network.mEnc.ljust(10, " "),
                    network.mCipher.ljust(11, " "),
                    str(network.mCh),
                    network.mVen.ljust(10, " "),
                    network.mSig,
                    network.mBeacons,
                    network.mSSID
                )
            )
        time.sleep(10)

def signal_handler(sig, frame):
    # curses.curs_set(True)
    print("\n\n[+] SIGINT RECIEVED...\n")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
