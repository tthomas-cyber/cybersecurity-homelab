# ReconScan — Custom Network Reconnaissance Tool

## Author
Tyler Thomas | github.com/tthomas-cyber

## Overview
A custom Python network reconnaissance tool built to automate the
initial scanning phase of a penetration test. Combines host discovery,
port scanning, service banner grabbing, and vulnerability flagging
into a single lightweight script with no external dependencies beyond
Python standard library.

## Features
- ICMP host discovery
- TCP port scanning with threading for speed
- Service banner grabbing
- Known vulnerable version detection
- Clean terminal output and report generation

## Usage
```bash
python3 reconscan.py -t 192.168.56.0/24
python3 reconscan.py -t 192.168.56.101
python3 reconscan.py -t 192.168.56.101 -p 1-1000
```

## Legal Notice
Only use against systems you own or have explicit written authorization
to test. Unauthorized scanning is illegal.
