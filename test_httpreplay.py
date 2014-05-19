# -*- coding: utf-8 -*-
import unittest
import httpreplay


class TestHttp(unittest.TestCase):
    def test_request(self):
        r = httpreplay.interpret_http("POST / HTTP/1.0\r\nConnection: close\r\n\r\n1234", True)
        self.assertEqual(r.body, "1234")
