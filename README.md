httpreplay
==========

Replay HTTP requests from previously captures pcap files.

Run `./httpreplay.py --help` for rudimentary help.

Prerequisites
-------------

`scapy` must be installed.

Code was written against Debian's `python-scapy` 2.2.0-1.


Limitations
-----------

All HTTP traffic must run on port 80.

HTTP features that are likely not understood:

* Compression
* Encoding: chunked

Multiple requests per session should work, but this is untested with current code.

