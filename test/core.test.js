import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decode, encode, TYPE, CLASS } from '../src/index.js';

/**
 * Each test is self-contained: it builds a known wire message by hand or
 * via `encode`, decodes it, and asserts on the structure we actually produce.
 * No floats, no wall-clock, no invented API surface.
 */

function buildSimpleQuery() {
  // Header: id=0x1234, flags=0x0100 (RD set), counts = 1 question
  const header = Buffer.from([
    0x12, 0x34, // id
    0x01, 0x00, // flags: RD
    0x00, 0x01, // qdcount
    0x00, 0x00, // ancount
    0x00, 0x00, // nscount
    0x00, 0x00, // arcount
  ]);
  // QNAME: example (7) . com (3) . 0
  const qname = Buffer.from([
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d,
    0x00,
  ]);
  // QTYPE=A, QCLASS=IN
  const qfoot = Buffer.from([0x00, 0x01, 0x00, 0x01]);
  return Buffer.concat([header, qname, qfoot]);
}

test('decodes a simple query header and question', () => {
  const msg = decode(buildSimpleQuery());
  assert.equal(msg.header.id, 0x1234);
  assert.equal(msg.header.qr, 0);
  assert.equal(msg.header.opcode, 0);
  assert.equal(msg.header.rd, 1);
  assert.equal(msg.header.qdcount, 1);
  assert.equal(msg.header.ancount, 0);
  assert.deepEqual(msg.question, [
    { name: 'example.com', type: TYPE.A, class: CLASS.IN },
  ]);
  assert.deepEqual(msg.answer, []);
});

test('round-trips through encode/decode', () => {
  const original = buildSimpleQuery();
  const decoded = decode(original);
  const reencoded = encode(decoded);
  const redecoded = decode(reencoded);
  assert.deepEqual(redecoded, decoded);
});

test('encodes header flags correctly', () => {
  const buf = encode({
    header: { id: 0xabcd, qr: 1, opcode: 0, aa: 0, tc: 0, rd: 1, ra: 1, z: 0, rcode: 0 },
    question: [],
  });
  assert.equal(buf[0], 0xab);
  assert.equal(buf[1], 0xcd);
  // 0x8180 = QR|RA|RD(0x0100)|... Actually QR=0x8000 | RD=0x0100 | RA=0x0080 = 0x8180
  assert.equal(buf[2], 0x81);
  assert.equal(buf[3], 0x80);
});

test('decodes a response with an A record answer', () => {
  // Query for example.com, answer: example.com A 3600 93.184.216.34
  const header = Buffer.from([
    0x12, 0x34,
    0x81, 0x80, // QR=1, RD=1, RA=1
    0x00, 0x01, // qd
    0x00, 0x01, // an
    0x00, 0x00, 0x00, 0x00,
  ]);
  const q = Buffer.from([
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d, 0x00,
    0x00, 0x01, 0x00, 0x01,
  ]);
  // Answer: pointer to offset 12 (0xc00c), type A, class IN, ttl 3600, rdlen 4, IP bytes
  const answer = Buffer.from([
    0xc0, 0x0c, // name pointer to offset 12
    0x00, 0x01, // type A
    0x00, 0x01, // class IN
    0x00, 0x00, 0x0e, 0x10, // ttl 3600
    0x00, 0x04, // rdlen 4
    0x5d, 0xb8, 0xd8, 0x22, // 93.184.216.34
  ]);
  const buf = Buffer.concat([header, q, answer]);
  const msg = decode(buf);
  assert.equal(msg.answer.length, 1);
  const a = msg.answer[0];
  assert.equal(a.name, 'example.com');
  assert.equal(a.type, TYPE.A);
  assert.equal(a.class, CLASS.IN);
  assert.equal(a.ttl, 3600);
  assert.deepEqual(Array.from(a.rdata), [0x5d, 0xb8, 0xd8, 0x22]);
});

test('round-trips an answer record', () => {
  const ipBytes = Uint8Array.from([0x5d, 0xb8, 0xd8, 0x22]);
  const msg = {
    header: { id: 0x4242, qr: 1, rd: 1, ra: 1, rcode: 0 },
    question: [{ name: 'example.com', type: TYPE.A, class: CLASS.IN }],
    answer: [
      { name: 'example.com', type: TYPE.A, class: CLASS.IN, ttl: 300, rdata: ipBytes },
    ],
  };
  const buf = encode(msg);
  const decoded = decode(buf);
  assert.equal(decoded.answer[0].ttl, 300);
  assert.deepEqual(Array.from(decoded.answer[0].rdata), Array.from(ipBytes));
});

test('handles root domain name', () => {
  const buf = encode({
    header: { id: 0, qr: 0, rd: 0 },
    question: [{ name: '', type: TYPE.NS, class: CLASS.IN }],
  });
  const msg = decode(buf);
  assert.equal(msg.question[0].name, '');
});

test('rejects messages shorter than the header', () => {
  assert.throws(() => decode(Buffer.from([0, 0, 0, 0])), /too short/);
});

test('rejects a name compression loop', () => {
  // Two pointers that point at each other
  const header = Buffer.from([
    0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0,
  ]);
  // Pointer to offset 12 (which is right here)
  const ptr = Buffer.from([0xc0, 0x0c]);
  const buf = Buffer.concat([header, ptr]);
  assert.throws(() => decode(buf), /loop|jump/i);
});

test('encodes names without trailing dot', () => {
  const buf = encode({
    header: { id: 0 },
    question: [{ name: 'a.b.c', type: TYPE.A, class: CLASS.IN }],
  });
  const msg = decode(buf);
  assert.equal(msg.question[0].name, 'a.b.c');
});

test('preserves TTL as unsigned 32-bit', () => {
  const ttl = 0xffffffff; // max u32
  const buf = encode({
    header: { id: 1 },
    answer: [{ name: 'x', type: TYPE.A, class: CLASS.IN, ttl, rdata: Uint8Array.of(1, 2, 3, 4) }],
  });
  const msg = decode(buf);
  assert.equal(msg.answer[0].ttl, 4294967295);
});

test('decodes multiple questions and answers', () => {
  const buf = encode({
    header: { id: 7 },
    question: [
      { name: 'one.test', type: TYPE.A, class: CLASS.IN },
      { name: 'two.test', type: TYPE.AAAA, class: CLASS.IN },
    ],
    answer: [
      { name: 'one.test', type: TYPE.A, class: CLASS.IN, ttl: 60, rdata: Uint8Array.of(1, 1, 1, 1) },
      { name: 'two.test', type: TYPE.AAAA, class: CLASS.IN, ttl: 60, rdata: Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) },
    ],
  });
  const msg = decode(buf);
  assert.equal(msg.question.length, 2);
  assert.equal(msg.answer.length, 2);
  assert.equal(msg.question[1].type, TYPE.AAAA);
});

test('default header z field is zero', () => {
  const buf = encode({ header: { id: 0 }, question: [] });
  const msg = decode(buf);
  assert.equal(msg.header.z, 0);
});

test('empty message round-trips', () => {
  const msg = { header: { id: 0x55aa }, question: [], answer: [], authority: [], additional: [] };
  const buf = encode(msg);
  const out = decode(buf);
  assert.equal(out.header.id, 0x55aa);
  assert.equal(out.question.length, 0);
});
