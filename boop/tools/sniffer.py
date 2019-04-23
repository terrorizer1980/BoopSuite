
import os
import sys
import time
import random

import pyric.pyw as pyw

from boop.lib.sniffer import Sniffer
from boop.lib.types import *
from boop.lib.client import Client
from boop.lib.network import Network

def sniffer_command(
    interface, channel, frequency, no_clients, no_open, target
):
    start = time.time()

    app = Sniffer(interface, channel)

    # def appprinter(self):
    #     import curses

        
    #     def curses_window(stdscr):
    #         stdscr.clear()
    #         curses.noecho()
    #         curses.curs_set(False)
    #         curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)

    #         stdscr.addstr(
    #                 2, 0, 
    #                 "{0}{1}{2}{3}{4}{5}{6}{7}\n".format(
    #                     "Mac Addr".ljust(19, " "),
    #                     "Enc".ljust(10, " "),
    #                     "Cipher".ljust(12, " "),
    #                     "Ch".ljust(5, " "),
    #                     "Vendor".ljust(10, " "),
    #                     "Sig".ljust(5, " "),
    #                     "Bcns".ljust(8, " "),
    #                     "SSID"
    #                 ), curses.color_pair(1)
    #             )
            
    #         while True:
    #             stdscr.addstr(
    #                 0, 0, 
    #                 "Boop [{2}] T: [{0}] C: [{1}]\n\n".format(
    #                     round(time.time() - start, 2), self.channel, self.packets
    #                 ), curses.A_BOLD
    #             )
                
    #             stdscr.move(3, 0)
    #             line = 2
    #             for network in self.sniffer_map["AP"].values():
    #                 try:
    #                     stdscr.clrtoeol()
    #                     line += 1
                        
    #                     stdscr.addstr(line, 0, 
    #                         " {0}{1}{2}{3:<5}{4}{5:<5}{6:<8}{7}\n".format(
    #                             network.mMAC.ljust(19, " "),
    #                             network.mEnc.ljust(10, " "),
    #                             network.mCipher.ljust(11, " "),
    #                             network.mCh,
    #                             network.mVen.ljust(10, " "),
    #                             network.mSig,
    #                             network.mBeacons,
    #                             network.mSSID
    #                         ), curses.A_BOLD
    #                     )
    #                 except curses.error:
    #                     pass

    #             try:
    #                 line += 1
    #                 stdscr.clrtoeol()
    #                 stdscr.addstr(
    #                     line, 0, 
    #                     "\n{0}{1}{2}{3}{4}\n".format(
    #                         "Mac".ljust(19, " "),
    #                         "AP Mac".ljust(19, " "),
    #                         "Noise".ljust(7, " "),
    #                         "Sig".ljust(5, " "),
    #                         "AP SSID"
    #                     ), curses.color_pair(1)
    #                 )
    #                 line += 1
    #             except curses.error:
    #                 pass


    #             for client in self.sniffer_map["CL"]:
    #                 line += 1
    #                 try:
    #                     stdscr.clrtoeol()
    #                     stdscr.addstr(line, 0, "client")
    #                 except curses.error:
    #                     pass

    #             stdscr.clrtobot()
    #             stdscr.refresh()
    #             time.sleep(4.5)

    #     curses.wrapper(curses_window)

    # app.printer = appprinter

    app.run()
