#! /usr/bin/python3

from __future__ import division
import struct
import sys
from binascii import unhexlify
from datetime import datetime, timedelta

nt_timestamp = struct.unpack("<Q", unhexlify(sys.argv[1]))[0]
epoch = datetime(1601, 1, 1, 0, 0, 0)
nt_datetime = epoch + timedelta(microseconds=nt_timestamp / 10)

print(nt_datetime.strftime("%c"))
