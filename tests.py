#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Anggit Arfanto

import asyncio
import socket
import threading
import time
import unittest

from http.server import HTTPServer, BaseHTTPRequestHandler

from netizen import HTTPClient


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.request_version != 'HTTP/1.1':
            self.protocol_version = 'HTTP/1.0'

        if self.path == '/timeout':
            self.send_response(200)
            self.end_headers()
        elif self.path == '/redirect':
            self.send_response(301)
            self.send_header('Location', '/json')
            self.send_header('Content-Length', '0')
            self.send_header('Set-Cookie', 'foo=bar')
            self.end_headers()
        elif self.path == '/json':
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')

            body = b'{"message": "Forbidden"}'
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()

            self.wfile.write(body)
        elif self.path == '/headers/bad/1':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Transfer-Encoding', 'chunked')

            for i in range(20):
                self.send_header('Set-Cookie', 'c' * 4096)

            self.end_headers()
        elif self.path == '/chunked':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            self.wfile.write(b'5\r\nBEGIN\r\n')

            for i in range(1, 96):
                self.wfile.write(b'%X' % i)

                self.wfile.write(b'\r')
                time.sleep(0.01)
                self.wfile.write(b'\n')

                self.wfile.write(bytes(range(32, i + 32)))

                self.wfile.write(b'\r')
                time.sleep(0.01)
                self.wfile.write(b'\n')

            self.wfile.write(b'3;EXT\r\nEND\r\n')
            self.wfile.write(b'0\r\n\r\n')
        elif self.path == '/chunked/bad/1':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            self.wfile.write(b'X' * 65)
        elif self.path == '/chunked/bad/2':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()

            self.wfile.write(b'2\r\nAB\r')
            time.sleep(0.1)
            self.wfile.write(b'X')
        else:  # Content-Length
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')

            body = b'BEGIN' + bytes(range(32, 127)) + b'END'
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()

            self.wfile.write(body)

    def do_POST(self):
        length = self.headers.get('Content-Length', 0)
        body = self.rfile.read(int(length))

        self.send_response(200)

        if self.request_version == 'HTTP/1.1':
            self.send_header('Content-Length', length)

        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class TestHTTPClient(unittest.TestCase):
    def setUp(self):
        print('\r\n[', self.id(), ']')

        self.client = HTTPClient('localhost', 27000)

    def test_get_content_length(self):
        with self.client:
            response = self.client.send(b'GET / HTTP/1.0')
            body = response.body()

            self.assertTrue(body.startswith(b'BEGIN'))
            self.assertTrue(body.endswith(b'END'))
            self.assertEqual(response.body(), b'')

    def test_get_content_length_async(self):
        async def main():
            async with self.client:
                response = await self.client.send(b'GET / HTTP/1.0')
                body = await response.body()

                self.assertTrue(body.startswith(b'BEGIN'))
                self.assertTrue(body.endswith(b'END'))
                self.assertEqual(await response.body(), b'')

        asyncio.run(main())

    def test_get_chunked(self):
        with self.client:
            response = self.client.send(b'GET /chunked HTTP/1.1')
            body = response.body()

            self.assertTrue(body.startswith(b'BEGIN'))
            self.assertTrue(body.endswith(b'END'))
            self.assertEqual(response.body(), b'')

    def test_get_chunked_async(self):
        async def main():
            async with self.client:
                response = await self.client.send(b'GET /chunked HTTP/1.1')
                body = await response.body()

                self.assertTrue(body.startswith(b'BEGIN'))
                self.assertTrue(body.endswith(b'END'))
                self.assertEqual(await response.body(), b'')

        asyncio.run(main())

    def test_post_no_content_length(self):
        with self.client:
            response = self.client.send(b'POST / HTTP/1.0', body=b'foo=bar')

            self.assertEqual(response.body(), b'foo=bar')

    def test_post_continue(self):
        with self.client:
            response = self.client.send(
                b'POST / HTTP/1.1',
                b'Content-Length: 7',
                b'Expect: 100-continue'
            )

            self.assertEqual(response.body(), b'')
            self.assertEqual(response.status, 100)
            self.assertEqual(response.message, b'Continue')

            self.client.sendall(b'foo=bar')

            self.assertEqual(response.body(), b'foo=bar')
            self.assertEqual(response.status, 200)
            self.assertEqual(response.message, b'OK')

        async def main():
            async with self.client:
                response = await self.client.send(
                    b'POST / HTTP/1.1',
                    b'Content-Length: 7',
                    b'Expect: 100-continue'
                )

                self.assertEqual(await response.body(), b'')
                self.assertEqual(response.status, 100)
                self.assertEqual(response.message, b'Continue')

                await self.client.sendall(b'foo=bar')
                response = await self.client.end()  # optional

                self.assertEqual(await response.body(), b'foo=bar')
                self.assertEqual(response.status, 200)
                self.assertEqual(response.message, b'OK')

        asyncio.run(main())

    def test_get_json(self):
        with self.client:
            response = self.client.send(b'GET /json HTTP/1.1')

            self.assertEqual(response.status, 403)
            self.assertEqual(response.message, b'Forbidden')
            self.assertEqual(response.json()['message'], 'Forbidden')

    def test_get_json_async(self):
        async def main():
            async with self.client:
                response = await self.client.send(b'GET /json HTTP/1.1')

                self.assertEqual(response.status, 403)
                self.assertEqual(response.message, b'Forbidden')
                self.assertEqual(
                    (await response.json())['message'], 'Forbidden'
                )

        asyncio.run(main())

    def test_headers(self):
        with self.client:
            self.client.update_header(b'User-Agent: Mozilla/5.0')
            response = self.client.send(b'GET / HTTP/1.1')
            line, header, body = response.request
            print('->', response.request)
            print('<-', response.headers)

            self.assertEqual(dict(response.header.getheaders())[b'date'],
                             response.headers[b'date'][0])
            self.assertTrue(b'\r\nUser-Agent: netizen/' not in header)
            self.assertTrue(b'\r\nUser-Agent: Mozilla/' in header)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.message, b'OK')
            self.assertEqual(response.url, b'')

            response.body()

            exc = None

            try:
                self.client.send(b'GET /headers/bad/1 HTTP/1.0')
            except Exception as e:
                exc = e

            self.assertEqual(str(exc), 'response header too large')

    def test_get_redirect(self):
        with self.client:
            response = self.client.send(b'GET /redirect HTTP/1.1')
            line, header, body = response.request
            print('->', response.request)

            self.assertEqual(response.status, 301)
            self.assertEqual(response.message, b'Moved Permanently')
            self.assertTrue(b'\r\nCookie: foo=bar' not in header)

            response.body()

            response = self.client.send(b'GET %s HTTP/1.0' % response.url)
            line, header, body = response.request
            print('->', response.request)

            self.assertEqual(response.status, 403)
            self.assertEqual(response.message, b'Forbidden')
            self.assertTrue(b'\r\nCookie: foo=bar' in header)

            response.body()

    def test_get_body_too_large(self):
        with self.client:
            response = self.client.send(b'GET /json HTTP/1.1')

            with self.assertRaises(ValueError):
                response.json(max_size=2)

            for _ in response:
                pass

        with self.client:
            response = self.client.send(b'GET /chunked HTTP/1.1')

            with self.assertRaises(ValueError):
                response.body(max_size=1)

            for _ in response:
                pass

        async def main():
            async with self.client:
                response = await self.client.send(b'GET /chunked HTTP/1.1')

                with self.assertRaises(ValueError):
                    await response.body(max_size=1)

                async for _ in response:
                    pass

        asyncio.run(main())

    def test_post_defer_body(self):
        with self.client:
            self.client.send(b'POST / HTTP/1.0', b'Content-Length: 4')
            self.client.sendall(b'EOF\n')

            response = self.client.end()

            self.assertEqual(response.status, 200)
            self.assertEqual(response.message, b'OK')
            self.assertEqual(response.body(), b'EOF\n')
            self.assertEqual(self.client.recv(4096), b'')

        async def main():
            async with self.client:
                await self.client.send(
                    b'POST / HTTP/1.0',
                    b'Content-Length: 4'
                )
                await self.client.sendall(b'EOF\n')

                response = await self.client.end()

                self.assertEqual(response.status, 200)
                self.assertEqual(response.message, b'OK')
                self.assertEqual(await response.body(), b'EOF\n')
                self.assertEqual(await self.client.recv(4096), b'')

        asyncio.run(main())

    def test_connect_timeout(self):
        with self.assertRaises(socket.timeout):
            with HTTPClient('192.0.2.1', 12345, timeout=1):
                pass

        async def main():
            async with HTTPClient('192.0.2.1', 12345, timeout=1):
                pass

        with self.assertRaises(socket.timeout):
            asyncio.run(main())

    def test_connect_retries(self):
        with self.assertRaises(OSError):
            with HTTPClient('example.invalid', 80, timeout=1, retries=1):
                pass

        async def main():
            async with HTTPClient('example.invalid', 80, timeout=1, retries=1):
                pass

        with self.assertRaises(OSError):
            asyncio.run(main())

    def test_send_retries(self):
        with self.client:
            self.client.sock.close()

            with self.assertRaises(OSError):
                self.client.send(b'GET / HTTP/1.1')

        with HTTPClient('127.0.0.1', 27000, retries=1) as client:
            client.sock.close()

            response = client.send(b'GET / HTTP/1.1')
            body = response.body()

            self.assertTrue(body.startswith(b'BEGIN'))
            self.assertTrue(body.endswith(b'END'))

        async def main():
            async with self.client:
                self.client.sock.close()

                with self.assertRaises(OSError):
                    await self.client.send(b'GET / HTTP/1.1')

            async with HTTPClient('127.0.0.1', 27000, retries=1) as client:
                client.sock.close()

                response = await client.send(b'GET / HTTP/1.1')
                body = await response.body()

                self.assertTrue(body.startswith(b'BEGIN'))
                self.assertTrue(body.endswith(b'END'))

        asyncio.run(main())

    def test_recv_timeout(self):
        with HTTPClient('127.0.0.1', 27000, timeout=1) as client:
            response = client.send(b'GET /timeout HTTP/1.1')

            with self.assertRaises(socket.timeout):
                response.body()

    def test_bad_chunked(self):
        with self.client:
            response = self.client.send(b'GET /chunked/bad/1 HTTP/1.1')
            exc = None

            try:
                response.body()
            except Exception as e:
                exc = e

            self.assertEqual(str(exc), 'bad chunked encoding: no chunk size')

            response = self.client.send(b'GET /chunked/bad/2 HTTP/1.1')

            try:
                response.body()
            except Exception as e:
                exc = e

            self.assertEqual(
                str(exc),
                'bad chunked encoding: invalid chunk terminator'
            )


if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 27000), EchoHandler)

    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    try:
        unittest.main()
    finally:
        server.shutdown()
        thread.join()
