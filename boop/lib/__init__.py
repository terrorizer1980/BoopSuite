import os, re

import pyric.pyw as pyw

ROOT = os.geteuid() == 0

MWINTERFACES = [x for x in pyw.winterfaces() if pyw.modeget(x) == "monitor"]
INTERFACES = [x for x in pyw.interfaces()]

BAD_MAC = [
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",  # Multicast
    "01:80:c2:00:00:00",  # Multicast
    "01:00:5e",  # Multicast
    "01:80:c2",  # Multicast
    "33:33",  # Multicast
]

MACFILTER = "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"

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

# This is for the future ;)
WPS_ATTRIBUTES = {
    0x104A : {'name' : 'Version                          ', 'type' : 'hex'},
    0x1044 : {'name' : 'WPS State                        ', 'type' : 'hex'},
    0x1057 : {'name' : 'AP Setup Locked                  ', 'type' : 'hex'},
    0x1041 : {'name' : 'Selected Registrar               ', 'type' : 'hex'},
    0x1012 : {'name' : 'Device Password ID               ', 'type' : 'hex'},
    0x1053 : {'name' : 'Selected Registrar Config Methods', 'type' : 'hex'},
    0x103B : {'name' : 'Response Type                    ', 'type' : 'hex'},
    0x1047 : {'name' : 'UUID-E                           ', 'type' : 'hex'},
    0x1021 : {'name' : 'Manufacturer                     ', 'type' : 'str'},
    0x1023 : {'name' : 'Model Name                       ', 'type' : 'str'},
    0x1024 : {'name' : 'Model Number                     ', 'type' : 'str'},
    0x1042 : {'name' : 'Serial Number                    ', 'type' : 'str'},
    0x1054 : {'name' : 'Primary Device Type              ', 'type' : 'hex'},
    0x1011 : {'name' : 'Device Name                      ', 'type' : 'str'},
    0x1008 : {'name' : 'Config Methods                   ', 'type' : 'hex'},
    0x103C : {'name' : 'RF Bands                         ', 'type' : 'hex'},
    0x1045 : {'name' : 'SSID                             ', 'type' : 'str'},
    0x102D : {'name' : 'OS Version                       ', 'type' : 'str'}
}