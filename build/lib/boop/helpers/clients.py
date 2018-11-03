class Client:

    def __init__(self, mac, bssid, rssi, essid):

        self.mMAC = mac
        self.mBSSID = bssid
        self.mSig = rssi
        self.mNoise = 1
        self.mESSID = essid
        return

    def __add__(self, value=1):

        self.mNoise += value
        return

    def __eq__(self, other):

        return True if other == self.mMac else False
