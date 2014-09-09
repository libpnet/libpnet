# Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

import sys
from scapy.all import Ether, IP, UDP, Padding, sendp

iface = sys.argv[1]
dst = sys.argv[2]

ether = Ether(dst = dst, type = 0x0800)
ip = IP(ttl = 4, proto = 17, src = '127.0.0.1', dst = '127.0.0.1')
udp = UDP(sport = 1234, dport = 1234)

# pad to 64 bytes
pad = Padding(load = '\0' * 17)

sendp(ether / ip / udp / "pymsg" / pad, iface = iface, loop=1)
