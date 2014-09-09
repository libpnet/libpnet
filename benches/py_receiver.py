# Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

from datetime import datetime
import sys
from scapy.all import sniff

iface = sys.argv[1]
timestamps = []

now = datetime.now()
original_seconds = (now.hour * 60 * 60) + (now.minute * 60) + now.second
timestamps.append(now.microsecond)

for i in range(0, 200):
    sniff(iface = iface, count = 1000, store = 0)
    now = datetime.now()
    seconds = (now.hour * 60 * 60) + (now.minute * 60) + now.second
    timestamp = 1000000 * (seconds - original_seconds) + now.microsecond
    timestamps.append(timestamp)

# We only capture 200 * 1_000 packets with Python, since it captures packets 1000x slower than C
# or Rust.
for (a, b) in zip(timestamps, timestamps[1:]):
    print (b - a) / 1000.0

