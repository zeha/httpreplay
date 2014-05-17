#!/usr/bin/env python
# httpreplay - replay pcap files containing http requests
# Likely broken: multiple requests per session, compression, chunked.
# Copyright 2014 Christian Hofstaedtler.

from scapy.layers.inet import TCP, IP
from scapy.utils import rdpcap
import socket
import sys


class HttpRequest(object):
    def __init__(self, method, url, version, headers, body):
        self.method = method
        self.url = url
        self.version = version
        self.headers = headers
        self.body = body

    def __repr__(self):
        return '<HttpRequest method=%r url=%r headers=%r body=%r>' % (
            self.method, self.url, self.headers, self.body
        )

    def to_payload(self):
        return "%s %s %s\r\n%s\r\n\r\n%s" % (
            self.method, self.url, self.version, "\r\n".join([': '.join(h) for h in self.headers]), self.body
        )


class HttpResponse(object):
    def __init__(self, version, code, status, headers, body):
        self.version = version
        self.code = code
        self.status = status
        self.headers = headers
        self.body = body

    def __repr__(self):
        return '<HttpResponse code=%r status=%r headers=%r body=%r>' % (
            self.code, self.status, self.headers, self.body
        )


def interpret_http(p, is_client_packet):
    lines = p.split("\r\n")
    end_of_headers = lines.index('')
    headers = [l.split(': ', 1) for l in lines[1:end_of_headers]]
    start_of_body = sum([len(l) + 2 for l in lines[0:end_of_headers + 1]])
    line0_fields = lines[0].split(' ', 2)
    while len(line0_fields) < 3:
        line0_fields.append('')
    data = line0_fields + [headers, p[start_of_body:]]

    if is_client_packet:
        return HttpRequest(*data)
    else:
        return HttpResponse(*data)


def convert_http_payload(pkt_list):
    last_packet_is_client_packet = None
    last_payload = None
    interpreted = []
    for pkt in pkt_list:
        if not pkt[TCP].payload:
            continue

        is_client_packet = (pkt[TCP].dport == 80)
        if last_packet_is_client_packet == is_client_packet:
            last_payload += pkt.payload.load
        else:
            if last_payload is not None:
                interpreted.append(interpret_http(last_payload, last_packet_is_client_packet))
            last_packet_is_client_packet = is_client_packet
            last_payload = pkt.payload.load

    if last_payload is not None:
        interpreted.append(interpret_http(last_payload, last_packet_is_client_packet))

    return interpreted


def assemble_sessions(pkts, session_done_cb):
    sessions = {}
    for pkt in pkts:
        if not pkt[TCP]:
            continue
        if pkt[TCP].sport != 80 and pkt[TCP].dport != 80:
            continue

        is_client_packet = (pkt[TCP].dport == 80)

        if is_client_packet:
            session_key = '%s_%d_%s_%d' % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        else:
            session_key = '%s_%d_%s_%d' % (pkt[IP].dst, pkt[TCP].dport, pkt[IP].src, pkt[TCP].sport)
        #print session_key, is_client_packet, pkt[TCP].payload

        if session_key in sessions:
            sessions[session_key].append(pkt)
        else:
            if pkt[TCP].flags == 2 and is_client_packet:  # SYN, initial contact
                sessions[session_key] = [pkt]
            else:
                #print session_key, 'dropping packet', pkt[TCP].payload
                continue

        if pkt[TCP].flags == 17:  # RST / FIN+ACK
            session_done_cb(sessions[session_key])
            del sessions[session_key]
            #print session_key, 'DONE', is_client_packet, pkt[TCP].flags, pkt[TCP].payload

    for pkts in sessions.values():
        session_done_cb(pkts)


def extract_http_data(pcap_file):
    pkts = rdpcap(pcap_file)
    streams = []
    assemble_sessions(pkts, lambda session_packets: streams.append(convert_http_payload(session_packets)))
    return streams


def print_http_data(http_data):
    for http in http_data:
        print repr(http)


def send_tcp(msg, server_addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(server_addr)
        sock.sendall(msg)
        data = ''
        while True:
            d = sock.recv(16384)
            if not d:
                break
            data += d
    except StandardError as ex:
        print ex
        return ''
    finally:
        sock.close()
    return data


def filter_server_headers(headers, ignore_list, strip_cookies_list):
    return [strip_cookies(h, strip_cookies_list) for h in headers if h[0].lower() not in ignore_list]


def strip_cookies(h, cookie_list):
    if h[0].lower() == 'set-cookie':
        cookie_data = h[1].split('; ')
        cookie_name, cookie_value = cookie_data[0].split('=', 1)
        if cookie_name in cookie_list:
            cookie_data[0] = cookie_name + '=<stripped>'
        return h[0], '; '.join(cookie_data)
    return h


def replay(streams, rewrite_dst, limit, ignore_headers, strip_cookies_list):
    rewrite_dst = rewrite_dst.split(':')
    if len(rewrite_dst) == 1:
        rewrite_dst = (rewrite_dst, 80)
    else:
        rewrite_dst[1] = int(rewrite_dst[1])
    rewrite_dst = tuple(rewrite_dst)

    if ignore_headers is None:
        ignore_headers = ['x-powered-by', 'date', 'server']
    else:
        ignore_headers = [h.lower() for h in ignore_headers]

    stats = {'sent': 0, 'ok': 0}

    for stream in streams:
        req = stream[0]
        if not isinstance(req, HttpRequest):
            continue
        orig_reply = stream[1]

        reply = interpret_http(send_tcp(req.to_payload(), rewrite_dst), False)
        stats['sent'] += 1

        reply.headers = sorted(reply.headers)
        orig_reply.headers = sorted(orig_reply.headers)
        # we ignore reply headers for now
        same = \
            (reply.code == orig_reply.code) and (reply.status == orig_reply.status) and \
            (reply.body == orig_reply.body) and \
            filter_server_headers(reply.headers, ignore_headers, strip_cookies_list) == \
            filter_server_headers(orig_reply.headers, ignore_headers, strip_cookies_list)

        if same:
            stats['ok'] += 1
            print '.',
        else:
            print
            print '*' * 70
            print "FAILED request:"
            print req
            print "Original reply:"
            print orig_reply
            print "Replayed reply:"
            print reply

        if limit is not None and stats['sent'] >= limit:
            break

    print 'Sent %d requests, OK: %d, Failed: %d' % (stats['sent'], stats['ok'], stats['sent'] - stats['ok'])
    if stats['sent'] == stats['ok']:
        return 0
    else:
        return 1


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--replay', action='store_true')
    parser.add_argument('--rewrite-dst')
    parser.add_argument('--limit', type=int)
    parser.add_argument('--ignore-header', dest='ignore_headers', action='append')
    parser.add_argument('--strip-cookie', dest='strip_cookies', action='append', default=['PHPSESSID'])
    parser.add_argument('file', metavar='PCAP-FILE')
    args = parser.parse_args()
    print "Reading data from pcap file", args.file
    streams = extract_http_data(args.file)
    if args.replay:
        return replay(streams, rewrite_dst=args.rewrite_dst, limit=args.limit, ignore_headers=args.ignore_headers,
                      strip_cookies_list=args.strip_cookies)
    else:
        print_http_data(streams)
        return 0

if __name__ == "__main__":
    sys.exit(main())
