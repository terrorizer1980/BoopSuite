#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click

import pyric.pyw as pyw

from colorama import Fore, Style

from boop.__version__ import __version__
from boop.tools.interfaces import interface_command
from boop.tools.modes import mode_command
from boop.tools.sniffer import sniffer_command


@click.group()
def main():
    print(f"BoopSuite {Fore.RED}{__version__}{Style.RESET_ALL}\n")


@main.command()
@click.argument(
    "interface", default="all", type=click.Choice([*pyw.winterfaces(), "all"])
)
@click.option("-v", "--verbose", count=True)
def interface(interface, verbose):
    interface_command(interface, verbose)


@main.command()
@click.argument("interface", type=click.Choice(pyw.winterfaces()))
@click.argument("mode", type=click.Choice(["managed", "monitor"]))
def mode(interface, mode):
    mode_command(interface, mode)


@main.command()
@click.argument(
    "interface",
    type=click.Choice(
        [
            x
            for x in pyw.winterfaces()
            if pyw.modeget(pyw.getcard(x)) == "monitor"
        ]
    ),
)
@click.option("-c", "--channel")
@click.option("-f", "--frequency")
@click.option("-n", "--no-clients")
@click.option("-o", "--no-open")
@click.option("-t", "--target")
def wsniffer(interface, channel, frequency, no_clients, no_open, target):
    sniffer_command(interface, channel, frequency, no_clients, no_open, target)


if __name__ == "__main__":
    main(prog_name="boop")
