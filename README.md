# Dragon Project local receiver

A low-level HTTP protocol workbench for a patched Dragon Project 1.8.9 client.

## Run

```text
pip install -r requirements.txt
python receiver.py
```

The server listens on:

```text
0.0.0.0:8080
```

Point your patched game at the PC, e.g.:

```text
http://192.168.0.245:8080/APP_HOST/
http://192.168.0.245:8080/IMG_HOST/resources/
http://192.168.0.245:8080/TABLE_HOST/resources/tables/
http://192.168.0.245:8080/CLAN_HOST/
```

## Endpoint layout

Every previously unknown APP_HOST API request creates an isolated file.

For:

```text
POST /APP_HOST/ajax/regist/checkregister
```

the server creates:

```text
./APP_HOST/ajax/regist/checkregister.py
```

For:

```text
POST /APP_HOST/ajax/quest/start
```

it creates:

```text
./APP_HOST/ajax/quest/start.py
```

The handler is:

```python
def handle(ctx):
    print(ctx.data_plaintext)

    return ctx.api_json({
        "error": 0,
        "result": {}
    })
```

The receiver imports handler files per request, so you can edit an endpoint
without restarting the server.

## What each handler receives

```text
ctx.data_plaintext       decrypted API request text
ctx.data_json            parsed JSON, when applicable
ctx.data_ciphertext      original Base64 AES ciphertext
ctx.form                 raw form fields
ctx.headers              HTTP headers
ctx.cookie               robpt cookie
ctx.request_id           rcToken
ctx.path                  complete request path
```

## Logging

Each request gets its own folder under:

```text
./logs/
```

Typical files:

```text
request.body.bin
request.json
data.ciphertext.txt
data.plaintext.txt
data.json
response.body.bin
response.json
response.text.txt
```

Exceptions are saved as:

```text
exception.txt
```

Responses are also tested for the Dragon Project table layout:

```text
[256-byte signature][zlib-compressed data]
```

If that succeeds, the decompressed data is saved as:

```text
response.after_256_zlib.txt
```

## Request decryption

The server implements the exact AES parameters identified in the 1.8.9
client:

```text
key:
    DEFAULT_NETWORK_HASH =
    ELqdT/y.pM#8+J##x7|3/tLb7jZhmqJ,

IV:
    yCNBH$$rCNGvC+#f

AES:
    AES-256-CBC
    PKCS#7
```

For a request with a known local `robpt` session, the receiver uses the
account's saved `userHash`. Otherwise it falls back to the hard-coded
DEFAULT_NETWORK_HASH.

That makes the earliest pre-authentication requests readable automatically.

## Response modes

Default:

```text
DPRO_RESPONSE_MODE=plain
python receiver.py
```

This returns normal JSON. It is intended for a client patched to bypass the
original response decrypt/decompress/signature processing.

To reproduce the original API response envelope:

```text
python receiver.py --generate-api-key
```

then:

```text
DPRO_RESPONSE_MODE=original
python receiver.py
```

The receiver will create:

```text
JSON
 -> zlib
 -> AES-256-CBC
 -> Base64
```

and an `x-signature` RSA/SHA256 header.

The generated public key must be placed in the client's
`Cipher.PUBLIC_KEY_STRING`.

## Server-list capture

The attached historical response is included exactly as captured:

```text
TABLE_HOST/resources/tables/serverlisttable.dat
```

It is **not** an ordinary API response.

The 1.8.9 client treats the first 256 bytes as the signature and zlib-decompresses
the remaining bytes. The decoded copy is:

```text
fixtures/serverlisttable.csv
```

The receiver also tolerates the double slash seen in the historical request:

```text
/resources/tables//serverlisttable.dat
```

because empty path components are ignored when locating the static file.

## Adding your own account behavior

The included StateStore is intentionally tiny. Endpoint handlers can use:

```python
account = ctx.server.state.create_account(device_id="...")
token = ctx.server.state.create_session(
    account["userId"],
    account["userHash"]
)
```

This is only scaffolding. The actual response fields should be filled in from
the client's observed requests and its decompiled response models rather than
guessed here.

## Workflow

1. Start the receiver.
2. Launch the patched APK.
3. Look at the first request.
4. Open the auto-created `.py` handler.
5. Inspect `data.plaintext.txt`.
6. Return the smallest response that satisfies the client.
7. Launch/retry and repeat.
