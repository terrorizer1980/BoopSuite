BoopSuite
===

# Synopsis:

BoopSuite is a wireless testing suite with extensible components

## The suite mimics flask!

```
from boop import *

from boop.hopper import Hopper
from boop.sniffer import BoopSniff

logging.getLogger("boop.sniffer").setLevel(logging.ERROR)

app = BoopSniff("wlx18d6c70f910d", Hopper("wlx18d6c70f910d"))
app.packets = 0

@app.handler(MGMT_DEAUTH)
def pkt(self, p):
    self.packets += 1
    return

@app.handler(MGMT_BEACON)
def pkt(self, p):
    self.packets += 1
    return

@app.printer()
def p(self):
    while True:
        print(self.packets)

app.run()

```

Import the modules you need, add handlers for the packets you want and parse away.


### Note:

I hope my project can aid everyone in their pentesting needs, and this project
is going to continue to grow as I add new handlers for additional packet types.

Changelog located in CHANGELOG file.

Hopefully others find it useful. If you do please email me and let me know I
would love to hear about it @ jayrad.security@protonmail.com

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=43LHEBX448Y48&lc=US&item_name=M1ND%2dB3ND3R&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)

Bitcoin Address: 1KJizmcsb7xRy9UwyYbgsy9NzSGdXMdaKy

Ethereum Address: 0xadd48827c47e809670737600f1456873bac31201

More ideas are welcome.
Email me @: jayrad.security@protonmail.com

# Requirements:

+ python3
+ everything in the requirements.txt

# Installation:

#### To install open a terminal and type:

```
git clone https://github.com/M1ND-B3ND3R/BoopSuite.git
cd BoopSuite/
sudo pip install -r requirements.txt
sudo python3 setup.py install
```

Execution will look like:

`sudo python3 -m boop`


# Motivation:

I am motivated by the want to be better. To prove others wrong and to prove
to myself that I can do things that were previously impossible to me.

# In Progress:

+ Code Fixes will be happening.
+ More functional API and better imports
+ recreating the old boopsuite sniffer in the __main__ file
+ argparsing for said file

# License:

MIT License
(c) MisterBianco, 2017
