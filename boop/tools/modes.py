import sys

import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl

from colorama import Fore, Style


def mode_command(interface, mode):
    card = pyw.getcard(interface)

    newcard = None
    if mode == "monitor":
        if pyw.modeget(card) == "monitor":
            sys.exit(
                f"{Fore.YELLOW}Card is already in monitor mode{Style.RESET_ALL}"
            )

        newcard = pyw.devset(card, get_next_name() + "mon")
        pyw.modeset(newcard, "monitor")
        pyw.up(newcard)
    else:
        if pyw.modeget(card) == "managed":
            sys.exit(
                f"{Fore.YELLOW}Card is already in managed mode{Style.RESET_ALL}"
            )
        newcard = pyw.devset(card, card.dev[:-3])
        pyw.modeset(newcard, "managed")
        pyw.up(newcard)
    print(
        f"{Fore.GREEN}New interface created: {Style.RESET_ALL}{newcard.dev} - {pyw.modeget(newcard)}"
    )
    return newcard


def get_next_name() -> str:
    name = "wlan"
    for i in range(10):
        if name + str(i) not in pyw.winterfaces():
            return name + str(i)
    else:
        raise ValueError("Couldnt find a suitable interface name")
