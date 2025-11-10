# Netizen
Netizen is a minimalist HTTP client with a symmetrical interface between async
and sync modes.
It doesn't aim to be feature-complete like *requests* or *httpx*.

Netizen is just enough for poking API endpoints and performing basic HTTP
operations or testing. It suits me, as I prefer working closely with sockets
and don't need high-level abstraction.

## Features
* Symmetrical interface, e.g. `client.send()` vs `await client.send()`
* ~500 lines of code
* No dependencies other than the [Python Standard Library](https://docs.python.org/3/library/index.html)

## Installation
```
pip install git+https://github.com/nggit/netizen.git
```

## Handling a JSON response body
```python
import asyncio

from netizen import HTTPClient


# sync
with HTTPClient('ip-api.com', 80) as client:
    response = client.send(b'GET /json HTTP/1.1')

    print(response.json())

# async
async def main():
    async with HTTPClient('ip-api.com', 80) as client:
        response = await client.send(b'GET /json HTTP/1.1')

        print(await response.json())

asyncio.run(main())
```

## Handling a raw response body with streaming
```python
import asyncio

from netizen import HTTPClient

client = HTTPClient('example.com', 80)


# sync
with client:
    response = client.send(b'GET / HTTP/1.1')

    for data in response:
        print('Received:', len(data), 'Bytes')

# async
async def main():
    async with client:
        response = await client.send(b'GET / HTTP/1.1')

        async for data in response:
            print('Received:', len(data), 'Bytes')

asyncio.run(main())
```

## Append request headers via `*args` also `body` parameter
```python
with HTTPClient('example.com', 80) as client:
    response = client.send(
        b'POST / HTTP/1.1',
        b'Content-Type: application/json',
        b'Content-Length: 14',
        body=b'{"foo": "bar"}'
    )

    print('Status code:', response.status)  # 403
    print('Reason phrase:', response.message)  # b'Forbidden'

# out of context, close the connection without reading the entire response body
```

If you don't specify any headers, then `Content-Length` will be automatically
inserted along with `Content-Type: application/x-www-form-urlencoded`.

```python
with HTTPClient('example.com', 80) as client:
    response = client.send(b'POST / HTTP/1.1', body=b'foo=bar')

```

## Send multiple requests within the same context/connection
```python
with HTTPClient('ip-api.com', 80) as client:
    # first request
    response = client.send(b'GET /json HTTP/1.1')

    # the first response body must be consumed before sending another one
    print(response.json())

    # second request
    response = client.send(b'GET / HTTP/1.1')

    for data in response:
        print('Received:', len(data), 'Bytes')
```

## Handling URL redirects
```python
from urllib.parse import urlparse


with HTTPClient('google.com', 443, ssl=True) as client:
    response = client.send(b'GET / HTTP/1.1')

    print('1. Status code:', response.status)  # 301
    print('1. Reason phrase:', response.message)  # b'Moved Permanently'
    print('1. Location:', response.url)  # b'http://www.google.com/'

    for data in response:
        pass

    if response.url:
        url = urlparse(response.url)

        if url.netloc:  # b'www.google.com' (different host)
            with HTTPClient(url.netloc.decode(), 443, ssl=True) as client:
                response = client.send(b'GET %s HTTP/1.1' % url.path)

                print('2. Status code:', response.status)  # 200
                print('2. Reason phrase:', response.message)  # b'OK'

                for data in response:
                    pass
        else:
            pass
```

## Working directly with socket using `client.sendall()` and `client.recv()`
```python
with HTTPClient('localhost', 8000, timeout=10) as client:
    response = client.send(
        b'GET /chat HTTP/1.1',
        b'Upgrade: WebSocket',
        b'Connection: Upgrade',
        b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
        b'Sec-WebSocket-Version: 13'
    )

    if response.status == 101:
        client.sendall(b'\x81\x0dHello, World!\x88\x02\x03\xe8')
        print('Received:', client.recv(4096))
```

## License
MIT License
