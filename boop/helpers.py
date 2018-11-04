from netaddr import *
from scapy.all import *

WPS_QUERY = {
    b"\x00\x10\x18": "Broadcom", # Broadcom */
	b"\x00\x03\x7f": "AtherosC", # Atheros Communications */
	b"\x00\x0c\x43": "RalinkTe", # Ralink Technology, Corp. */
    b"\x00\x17\xa5": "RalinkTe", # Ralink Technology Corp */
	b"\x00\xe0\x4c": "RealtekS", # Realtek Semiconductor Corp. */
	b"\x00\x0a\x00": "Mediatek", # Mediatek Corp. */
	b"\x00\x0c\xe7": "Mediatek", # Mediatek MediaTek Inc. */
	b"\x00\x1c\x51": "CelenoCo", # Celeno Communications */
	b"\x00\x50\x43": "MarvellS", # Marvell Semiconductor, Inc. */
	b"\x00\x26\x86": "Quantenn", # Quantenna */
	b"\x00\x09\x86": "LantiqML", # Lantiq/MetaLink */
	b"\x00\x50\xf2": "Microsof"
}

def get_rssi(decoded):

    try:
        rssi = -(256 - ord(decoded[-2:-1]))
    except:
        rssi = -(256 - ord(decoded[-4:-3]))

    if rssi < -100:
        return -1
    return rssi

def get_ssid(p):
    if p and u"\x00" not in "".join([str(x) if x < 128 else "" for x in p]):

        try:
            return p.decode("utf-8") # Remove assholes emojis in SSID's
        except:
            return unicode(p, errors='ignore')

    else:
        return (("< len: {0} >").format(len(p)))

def get_channel(packet):

    try:
        return str(ord(packet.getlayer(Dot11Elt, ID=3).info))

    except:
        dot11elt = packet.getlayer(Dot11Elt, ID=61)
        return ord(dot11elt.info[-int(dot11elt.len):-int(dot11elt.len)+1])

def get_security(packet):

    cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
    "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split("+")

    sec = ""
    cipher = None
    p_layer = ""

    try:
        p_layer = packet.getlayer(Dot11Elt, ID=48).info
        sec = "WPA2"

    except AttributeError:
        p_layer = packet.getlayer(Dot11Elt, ID=221).info

        if p_layer.startswith(b"\x00P\xf2\x01\x01\x00"):
            sec = "WPA"

    if not sec:
        # Check for wep
        if "privacy" in cap:
            sec = "WEP"

        elif not sec:
            return "OPEN", None

    if sec == "WPA2" and p_layer:

        if p_layer[8:12] == b"\x00\x0f\xac\x02":

            print(p_layer)
            # Broken becuase no one has a CCMP/TKIP network.
            cipher = "CCMP/TKIP" if temp[16:24] == b"\x00\x0f\xac\x04" else "TKIP"

        elif p_layer[8:12] == b"\x00\x0f\xac\x04":
            cipher = "CCMP"

    temp = packet.getlayer(Dot11Elt, ID=221).info

    for key in WPS_QUERY:
        if key in temp:
            sec += "/WPS"

    # print(sec, cipher)
    return sec, cipher

def get_vendor(addr3):
    try:
        return (EUI(addr3)).oui.registration().org
    except NotRegisteredError:
        return "-"

class AccessPoint:

    def __init__(
        self,
        ssid,
        enc,
        cipher,
        ch,
        mac,
        ven,
        sig
    ):

        self.ssid    = ssid
        self.enc     = enc
        self.cip     = cipher
        self.ch      = ch
        self.mac     = mac
        self.ven     = ven
        self.sig     = sig

        return

    def __eq__(self, other):
        return True if other == self.mMAC else False

class Client:

    def __init__(
        self,
        mac,
        bssid,
        rssi,
        essid
    ):

        self.mac    = mac
        self.bssid  = bssid
        self.sig    = rssi
        self.essid  = essid
        return

    def __eq__(self, other):
        return True if other == self.mMac else False
