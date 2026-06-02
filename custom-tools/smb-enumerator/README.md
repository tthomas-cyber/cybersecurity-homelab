# SMBEnum — Custom SMB Enumeration Tool

## Author
Tyler Thomas | github.com/tthomas-cyber

## Overview
A custom Python tool for enumerating SMB services on Windows
targets during penetration tests. Identifies shares, tests for
null session access, checks SMB signing configuration, and
enumerates domain information via SMB protocol.

## Why SMB Matters
SMB is present on virtually every Windows machine in an enterprise
environment. Misconfigurations like null sessions, unsigned SMB,
and exposed shares are among the most common findings in internal
penetration tests.

## Usage
```bash
python3 smbenum.py -t 192.168.56.102
python3 smbenum.py -t 192.168.56.102 -u Administrator -p Lab@dmin123!
```

## Legal Notice
Only use against systems you own or have explicit written
authorization to test.
