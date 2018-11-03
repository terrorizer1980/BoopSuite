class AccessPoint:

    def __init__(self, ssid, enc, cipher, ch, mac, ven, sig, p):

        self.mSSID = ssid
        self.mEnc = enc
        self.mCipher = cipher
        self.mCh = ch
        self.mMAC = mac
        self.mVen = ven[:8]
        self.mSig = sig
        self.mCapped = False

        self.mBeacons = 1

        self.frame2 = None
        self.frame3 = None
        self.frame4 = None
        self.replay_counter = None

        self.packets = [p]

        return

    def __add__(self, value=1):

        self.mBeacons += value
        return

    def __eq__(self, other):

        return True if other == self.mMAC else False
