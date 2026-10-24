"""Real macOS command output captured on a Mac (Darwin 25.4.0).

Only non-parsed identifiers (MAC/IP/gateway addresses) are scrubbed; the
`interface:` and `flags=` lines the parsers read are verbatim bytes.
"""

ROUTE_PUBLIC = '   route to: 1.1.1.1\ndestination: default\n       mask: default\n    gateway: 192.0.2.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0 \n'

ROUTE_LOOPBACK = '   route to: 127.0.0.1\ndestination: 127.0.0.1\n  interface: lo0\n      flags: <UP,HOST,DONE,LOCAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n   49152     49152         0         1         0         0     16384         0 \n'

ROUTE_V6_LOOPBACK = '   route to: ::1\ndestination: ::1\n  interface: lo0\n      flags: <UP,HOST,DONE,LLINFO,LOCAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         1         0         0     16384         0 \n'

IFCONFIG_L = 'lo0 gif0 stf0 anpi1 anpi0 en3 en4 en1 en2 bridge0 ap1 en0 awdl0 llw0 utun4 utun7 utun8 utun5 utun6 utun9 utun0 utun1 utun2 utun3\n'

IFCONFIG_LO0 = 'lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet6 2001:db8::1 prefixlen 128 \n\tinet6 2001:db8::1%lo0 prefixlen 64 scopeid 0x1 \n\tnd6 options=201<PERFORMNUD,DAD>\n'

IFCONFIG_EN0 = 'en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>\n\tether 02:00:00:00:00:00\n\tinet6 2001:db8::1%en0 prefixlen 64 secured scopeid 0xb \n\tinet 192.0.2.57 netmask 0xffffff00 broadcast 192.0.2.255\n\tinet6 2001:db8::1 prefixlen 64 autoconf secured \n\tnd6 options=201<PERFORMNUD,DAD>\n\tmedia: autoselect\n\tstatus: active\n'

IFCONFIG_UTUN4 = 'utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>\n'
