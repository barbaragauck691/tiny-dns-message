# tiny-dns-message

Encodes and decodes DNS wire-format messages (header, question, answer, authority, additional) with zero dependencies.

```js
import { decode, encode, TYPE, CLASS } from 'tiny-dns-message';

const query = encode({
  header: { id: 0x1234, rd: 1 },
  question: [{ name: 'example.com', type: TYPE.A, class: CLASS.IN }],
});

const msg = decode(query);
console.log(msg.question[0].name); // "example.com"
```

## Why

Existing DNS libraries tend to bundle record-type parsers, resolver I/O, and cache layers together. That's the wrong shape when you only need to turn bytes into a structured message and back — for example, when building a custom resolver, a proxy, or a fuzzer. This library does exactly that one job and stops.

The trade-off: RDATA is returned as raw bytes. Callers that want `1.2.3.4` from an A record must parse those four bytes themselves. The benefit is that the codec never lies about what it understands.

## Awkward edge

Names are encoded **without** compression pointers. This is valid per RFC 1035, and every conformant decoder must accept it, but some hand-rolled parsers assume pointers and break on uncompressed names. On decode, compression pointers are followed correctly and loops are rejected.

## Exports

- `decode(bytes)` → `{ header, question, answer, authority, additional }`
- `encode(message)` → `Buffer`
- `TYPE`, `CLASS`, `RCODE` — frozen constant maps for the common values

The `header` object has fields `id`, `qr`, `opcode`, `aa`, `tc`, `rd`, `ra`, `z`, `rcode`, `qdcount`, `ancount`, `nscount`, `arcount`. Records carry `name`, `type`, `class`, `ttl`, and `rdata` (a `Uint8Array`).
