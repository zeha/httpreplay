#!/usr/bin/env python
# httpreplay - replay pcap files containing http requests
# Copyright 2014 Christian Hofstaedtler.

from xml.etree.ElementTree import ElementTree, ParseError, SubElement
from cStringIO import StringIO


def preprocess(response):
    """
    Example response preprocessing function.
    This example sorts data in an XML output.
    """

    try:
        xml = ElementTree()
        root = xml.parse(StringIO(response.body))
        for row in root.findall('.//row'):
            cols = row.findall('./col')
            data = []
            for col in cols:
                data.append((col.get('name'), col.text))
            data = sorted(data)
            row.clear()
            for col in data:
                el = SubElement(row, 'col')
                el.set('name', col[0])
                el.text = col[1]
        buf = StringIO()
        xml.write(buf, xml_declaration=True, encoding='ISO-8859-1')
        response.body = buf.getvalue()
        return response
    except ParseError:
        return response
