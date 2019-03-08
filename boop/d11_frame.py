#[ Ripping trackerjacker like crazy ]#

from .oui import OUI

from scapy.all import *

class Dot11Frame:

    TO_DS = 0x1
    FROM_DS = 0x2

    def __init__(self, frame):
        self.frame = frame
        self.bssid = None
        self.ssid  = None
        self.signal = 0
        self.channel = 0
        self.frame_bytes = len(frame)

        to_ds = frame.FCfield & Dot11Frame.TO_DS != 0
        from_ds = frame.FCfield & Dot11Frame.FROM_DS != 0

        if to_ds and from_ds:
            self.dest = frame.addr3
            self.src  = frame.addr4
            
        elif to_ds:
            self.dest = frame.addr2
            self.src  = frame.addr3
            self.bssid = frame.addr1

        elif from_ds:
            self.dest = frame.addr3
            self.src  = frame.addr1
            self.bssid = frame.addr2

        else:
            self.dest = frame.addr1
            self.src  = frame.addr2
            self.bssid = frame.addr3
        
        if frame.haslayer(Dot11Elt) and (frame.haslayer(Dot11Beacon)) or frame.haslayer(Dot11ProbeResp):

            self.get_ssid()

        if frame.haslayer(RadioTap):
            self.get_signal()

        self.dest_vendor = OUI.get(self.dest[:8].replace(":", "").upper(), "-")
        self.src_vendor  = OUI.get( self.src[:8].replace(":", "").upper(), "-")

        if self.bssid:
            self.bssid_vendor = OUI.get(self.bssid[:8].replace(":", "").upper(), "-")
        else:
            self.bssid_vendor = None

    def get_ssid(self):
        try:
            self.ssid = self.frame[Dot11Elt].info.decode().replace("\x00", "")
        except UnicodeDecodeError:
            return (("< len: {0} >").format(len(self.frame[Dot11Elt].info)))
        
    def get_signal(self):
        try:
            self.signal = -(256 - ord(self.frame.notdecoded[-2:-1]))
        except:
            self.signal = -(256 - ord(self.frame.notdecoded[-4:-3]))

        if self.signal < -100:
            self.signal = -1

    def __str__(self) -> str:
        return f"Dot11Frame(type={self.frame.type}, subtype={self.frame.subtype})"
