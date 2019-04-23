import sys

import pyric.pyw as pyw
from colorama import Fore, Style


def interface_command(interface, verbose):
    faces = pyw.winterfaces() if interface == "all" else [interface]
    for face in faces:
        if face not in pyw.winterfaces():
            sys.exit(f"{face} is not an interface")

    print(f"{Fore.GREEN}Interfaces:{Fore.YELLOW}")
    for interface in faces:
        face = pyw.getcard(interface)
        up = Fore.YELLOW if pyw.isup(face) else Fore.RED

        print(f"  {up}{interface:<10} {Style.RESET_ALL}")
        if verbose >= 1:
            iinfo = pyw.ifinfo(face)
            for i in iinfo:
                print(
                    f"\t{i.title():<15} {Fore.CYAN}{iinfo[i]}{Style.RESET_ALL}"
                )
        if verbose >= 2:
            dinfo = pyw.devinfo(face)
            for d in dinfo:
                print(
                    f"\t{d.title():<15} {Fore.CYAN}{dinfo[d]}{Style.RESET_ALL}"
                )

        if verbose >= 3:
            pinfo = pyw.phyinfo(face)
            for p in pinfo:
                if type(pinfo[p]) == list:
                    print(
                        f"\t{p.title():<15} {Fore.CYAN}{', '.join(pinfo[p])}{Style.RESET_ALL}"
                    )
                elif p == "bands":
                    print(
                        f"\t{p.title():<15} {Fore.CYAN}{', '.join(pinfo[p].keys())}{Style.RESET_ALL}"
                    )
