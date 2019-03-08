import os

import pyric.pyw as pyw

ROOT = os.geteuid() == 0

MWINTERFACES = [x for x in pyw.winterfaces() if pyw.modeget(x) == "monitor"]
INTERFACES = [x for x in pyw.interfaces()]

MGMT_ASSOC_REQ    = (0, 0)
MGMT_ASSOC_RESP   = (0, 1)
MGMT_REASSOC_REQ  = (0, 2)
MGMT_REASSOC_RESP = (0, 3)
MGMT_PROBE_REQ    = (0, 4)
MGMT_PROBE_RESP   = (0, 5)
MGMT_BEACON       = (0, 8)
MGMT_ATIM         = (0, 9)
MGMT_DISASSOC     = (0, 10)
MGMT_AUTH         = (0, 11)
MGMT_DEAUTH       = (0, 12)

CTRL_POLL         = (1, 10)
CTRL_RTS          = (1, 11)
CTRL_CTS          = (1, 12)
CTRL_ACK          = (1, 13)
CTRL_CFEND        = (1, 14)
CTRL_CFECFA       = (1, 15)

DATA_ANY          = (2, (0,1,2,3,4,5,6,7,8,9,10,11))

BAD_MAC = [
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",                    # Multicast
    "01:80:c2:00:00:00",                    # Multicast
    "01:00:5e",                             # Multicast
    "01:80:c2",                             # Multicast
    "33:33"                                 # Multicast
]

FIVEHERTZ = [
    36, 40, 44, 48, 52,
    56, 60, 64, 100, 104,
    108, 112, 116, 132, 136,
    140, 149, 153, 157, 161, 165
]

MACFILTER = "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"