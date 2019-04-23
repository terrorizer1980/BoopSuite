# [ Ripping trackerjacker like crazy ]#

from netaddr import *

from scapy.all import *

from boop.lib import *

from pyric.utils import channels

class Dot11Frame:

    TO_DS = 0x1
    FROM_DS = 0x2

    def __init__(self, frame):
        self.frame = frame
        self.bssid = None
        self.ssid = None
        self.signal = frame.dBm_AntSignal
        self.channel = channels.ISM_24_F2C.get(frame.Channel, "-1")
        self.frame_bytes = len(frame)
        self.cipher = ""
        self.security = []

        # print(frame.Channel)

        to_ds = frame.FCfield & Dot11Frame.TO_DS != 0
        from_ds = frame.FCfield & Dot11Frame.FROM_DS != 0

        if to_ds and from_ds:
            self.dest = frame.addr3
            self.src = frame.addr4

        elif to_ds:
            self.dest = frame.addr2
            self.src = frame.addr3
            self.bssid = frame.addr1

        elif from_ds:
            self.dest = frame.addr3
            self.src = frame.addr1
            self.bssid = frame.addr2

        else:
            self.dest = frame.addr1
            self.src = frame.addr2
            self.bssid = frame.addr3

        if (
            frame.haslayer(Dot11Elt)
            and (frame.haslayer(Dot11Beacon))
            or frame.haslayer(Dot11ProbeResp)
        ):

            self.get_ssid()

        try:
            self.dest_vendor = EUI(self.dest).oui.registration().org[:8]
        except NotRegisteredError:
            self.dest_vendor = "NA"
        except TypeError:
            print(">", self.dest)

        try:
            self.src_vendor = EUI(self.src).oui.registration().org[:8]
        except NotRegisteredError:
            self.src_vendor = "NA"
        except TypeError:
            print(">>", self.src)

        if self.bssid:
            try:
                self.bssid_vendor = EUI(self.bssid).oui.registration().org[:8]
            except NotRegisteredError:
                self.bssid_vendor = "NA"
            except TypeError:
                print(">>>", self.bssid)
        else:
            self.bssid_vendor = "NA"

        # if frame.type == 0 and frame.subtype == 8:
        #     print("lasjdf")
        #     self.get_security()

    def get_ssid(self):
        # try:
        self.ssid = self.frame.info.decode().replace("\x00", "")
        if len(self.ssid) == 0:
            self.ssid = ("< len: {0} >").format(len(self.frame.info))
            
        # except UnicodeDecodeError:
        #     self.hidden.append(self.src)
        #     self.ssid = ("< len: {0} >").format(len(self.frame[Dot11Elt].info))

    # def get_signal(self):
    #     self.signal = self.frame.dBm_AntSignal
    #     # try:
    #     #     self.signal = -(256 - ord(self.frame.notdecoded[-2:-1]))
    #     # except:
    #     #     self.signal = -(256 - ord(self.frame.notdecoded[-4:-3]))

    #     # if self.signal < -100:
    #     #     self.signal = -1

    def __str__(self) -> str:
        return (
            f"Dot11Frame(type={self.frame.type}, subtype={self.frame.subtype})"
        )

    def network_stats(self):
        summary = {}
        crypto = set()
        akmsuite_types = {
            0x00: "Reserved",
            0x01: "802.1X",
            0x02: "PSK"
        }
        p = self.frame["Dot11Beacon"].payload
        while isinstance(p, Dot11Elt):
            # if p.ID == 0:
            #     self.ssid = plain_str(p.info)
            if isinstance(p, Dot11EltRSN):
                if p.akm_suites:
                    auth = akmsuite_types.get(p.akm_suites[0].suite)
                    self.cipher = auth
                    self.security = ("WPA2")
                else:
                    self.security = ("WPA2")
            elif p.ID == 221:
                if isinstance(p, Dot11EltMicrosoftWPA) or \
                        p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    if p.akm_suites:
                        auth = akmsuite_types.get(p.akm_suites[0].suite)
                        self.cipher = auth
                        self.security = ("WPA2")
                    else:
                        self.security = ("WPA")
                try:
                    for key in WPS_QUERY:
                        if key in p.info:
                            index = p.info.index(key)
                            if index != 18:
                                print("WPS index: "+str(p.info.index(key)))
                            self.security += "/WPS"
                except AttributeError:
                    pass
            p = p.payload
        if not self.security:
            if self.frame.cap.privacy:
                self.security = ("WEP")
            else:
                self.security = ("OPN")

        
        return

    # def get_security(self):
    #     cap = self.frame.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
    #     "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split("+")

    #     sec = ""
    #     cipher = None
    #     p_layer = ""

    #     # print(self.frame.notdecoded[-2:-1])

    #     try:
    #         p_layer = self.frame.getlayer(Dot11Elt, ID=48).info
    #         sec = "WPA2"

    #     except AttributeError:
    #         try:
    #             p_layer = self.frame.getlayer(Dot11Elt, ID=221).info
    #         except AttributeError:
    #             print(self.frame.show())

    #         if p_layer.startswith(b"\x00P\xf2\x01\x01\x00"):
    #             sec = "WPA"

    #     # try:
    #     #     print(">>>>>", self.frame.getlayer(Dot11Elt, ID=48)[8:12])
    #     #     print(">>", p_layer)
    #     # except:
    #     #     try:
    #     #         print(">>>>>", self.frame.getlayer(Dot11Elt, ID=221)[8:12])
    #     #     except:
    #     #         pass

    #     if not sec:
    #         # Check for wep
    #         if "privacy" in cap:
    #             sec = "WEP"

    #         elif not sec:
    #             self.security = "OPEN"
    #             self.cypher = ""
    #             return

    #     if sec == "WPA2" and p_layer:

    #         # print(p_layer)
    #         if p_layer[8:12] == b"\x00\x0f\xac\x02":

                
    #             # Broken becuase no one has a CCMP/TKIP network.
    #             cipher = "CCMP/TKIP" if temp[16:24] == b"\x00\x0f\xac\x04" else "TKIP"

    #         elif p_layer[8:12] == b"\x00\x0f\xac\x04":
    #             cipher = "CCMP"

    #     temp = self.frame.getlayer(Dot11Elt, ID=221).info
    #     # print(temp)
    #     for key in WPS_QUERY:
    #         if key in temp:
    #             sec += "/WPS"

    #     # print(sec, cipher)
    #     print(Dot11Beacon(self.frame).network_stats())
    #     self.security = sec
    #     self.cipher = cipher or "?"