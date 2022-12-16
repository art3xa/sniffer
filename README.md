# Sniffer

Version 0.1

Author: Artyom Romanov (artem.romanov.03@bk.ru)

Reviewers:

## Description
 - Sniffer
 - Support Linux or WSL
 - Support TCP, UDP, ICMP
 - Work with root privileges
 - Write to pcap file


# Usage
- Working with the program is very simple.

`sniffer.py [-h] [-i INTERFACE] [-f FILE]`

Run on Linux:
`sudo python3 sniffer.py [OPTIONS]`


Run tests:
`python3 -m unittest src/tests/tests.py`

# Options
Options `[OPTIONS]` must be the following:

`-i, --interface` — interface

`-f, --file` — file (sniffer.pcap by default)

`-h, --help` — show this help message and exit

# Examples
`sudo python3 sniffer.py`

`sudo python3 sniffer.py -i eth0`

`sudo python3 sniffer.py -i eth0 -f sniffer.pcap`

`sudo python3 sniffer.py -i eth0 -f my_sniffer.pcap`

## Functionality
- Sniffer
- Write to pcap file
- Support Linux or WSL
- Tests

## Structure
- `sniffer.py` — main file
- `src/` — source files
- `tests/` — tests
- `README.md` — this file
- `src/modules/` — modules
- `src/modules/logic/Parser.py` — Parser UDP, TCP, ICMP etc
- `src/modules/logic/Program.py` — Logic
- `src/modules/helpers/Timer.py` — Timer for output and pcap file
- `src/modules/helpers/PcapWriter.py` — Write to pcap file
- `src/modules/helpers/SocketAPI.py` — Socket
- `src/modules/console/ArgParser.py` — Arguments parser
- `src/modules/console/Visualizer.py` — Console output visualizer
- `src/tests/tests.py` — Tests

## Realization


# Requirements
- Python 3.8+
