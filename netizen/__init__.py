# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Anggit Arfanto

import asyncio
import socket
import ssl

from .http_response import HTTPResponse

__version__ = '0.0.1'


def getfamily(host, port=None):
    if port is None:
        return socket.AF_UNIX, host

    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    return family, (host, port)


class Client:
    def __init__(self, host, port=None, *, timeout=30, loop=None, ssl=None,
                 server_hostname=None):
        self.loop = loop
        self.host = host
        self.family, self.address = getfamily(host, port)
        self.timeout = timeout or None
        self.ssl = ssl  # can be True, ssl.SSLContext, or None
        self.server_hostname = server_hostname or host
        self.sock = None

    def __enter__(self):
        self.sock = socket.socket(self.family, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)

        try:
            self.sock.connect(self.address)
        except socket.timeout:
            self.sock.close()
            raise

        if self.ssl:
            if not isinstance(self.ssl, ssl.SSLContext):
                self.ssl = ssl.create_default_context()

            self.sock = self.ssl.wrap_socket(
                self.sock,
                server_hostname=self.server_hostname
            )

        return self

    def __exit__(self, exc_type, exc, tb):
        self.sock.close()

    async def __aenter__(self):
        if self.loop is None:
            self.loop = asyncio.get_running_loop()

        self.sock = socket.socket(self.family, socket.SOCK_STREAM)
        self.sock.setblocking(False)

        task = self.loop.create_task(
            self.loop.sock_connect(self.sock, self.address)
        )
        timer = self.loop.call_later(self.timeout, task.cancel)

        try:
            await task
        except asyncio.CancelledError as exc:
            self.sock.close()
            raise socket.timeout from exc
        finally:
            timer.cancel()

        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.sock.close()

    def recv(self, n):
        if self.sock.getblocking():
            return self.sock.recv(n)

        return self.loop.sock_recv(self.sock, n)

    def sendall(self, data):
        if self.sock.getblocking():
            return self.sock.sendall(data)

        return self.loop.sock_sendall(self.sock, data)


class HTTPClient(Client):
    def __init__(self, host, port=None, **kwargs):
        super().__init__(host, port, **kwargs)

        if port is None:
            host = b'localhost'
        else:
            host = b'%s:%d' % (host.encode('latin-1'), port)

        self.headers = [
            b'Host: ' + host,
            b'User-Agent: netizen/' + __version__.encode('latin-1'),
            b'Accept: */*'
        ]

    def delete_header(self, name):
        i = len(self.headers)

        while i > 0:
            i -= 1

            if self.headers[i].startswith(b'%s:' % name):
                del self.headers[i]

    def update_header(self, value):
        name, _ = value.split(b':', 1)

        self.delete_header(name)
        self.headers.append(value)

    def update_cookie(self, value):
        name, _ = value.split(b'=', 1)

        for i, header in enumerate(self.headers):
            if header.startswith(b'Cookie: %s=' % name):
                self.headers[i] = b'Cookie: %s' % value
                break
        else:
            self.headers.append(b'Cookie: %s' % value)

    def send(self, line, *args, body=b''):
        headers = list(args)

        if body and not headers:
            headers.append(b'Content-Type: application/x-www-form-urlencoded')
            headers.append(b'Content-Length: %d' % len(body))

        header = b'\r\n'.join(self.headers + headers)
        pending = body == b'' and b'\r\nContent-Length:' in header

        return HTTPResponse(self, line, header, body, pending=pending)
