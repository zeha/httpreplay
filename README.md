httpreplay
==========

Replay HTTP requests from previously captured pcap files.

Run `./httpreplay.py --help` for rudimentary help.

Usage example
-------------

Replay data from file `http1.pcap` to server on `localhost:8402`, while
ignoring a few headers and dropping the value of the cookie named `PHPSESSID`:

```
./httpreplay.py --replay localhost:8402 \
  --ignore-header x-powered-by --ignore-header date \
  --ignore-header server --ignore-header connection \
  --ignore-header content-length --strip-cookie PHPSESSID \
  http1.pcap
```

Use an external preprocess function named `preprocess` from a module called
`example_preprocess` to preprocess responses for replay comparison:

```
./httpreplay.py --replay localhost:8402 \
  --load example_preprocess \
  --preprocess-response example_preprocess.preprocess \
  http2.pcap
```


Input file preparation
----------------------

The input file must be in `pcap` format. Wireshark and tshark use `pcapng`,
so their output files need to be converted.

Also, the input file should not contain retransmissions.

This `tshark` command line turns any understood file into a `pcap` file
and skips retransmitted packets:

```
tshark -n -F pcap -Y '!tcp.analysis.retransmission and !tcp.analysis.out_of_order' \
-r in.pcap -w out.pcap
```


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

