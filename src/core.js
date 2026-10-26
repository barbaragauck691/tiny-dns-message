/**
 * @file DNS wire-format message encoding and decoding.
 */

/**
 * RFC 1035 §3.2.2 — CLASS field values. Only the classes a stub resolver
 * will ever see are listed; unknown classes are carried as raw integers so
 * callers can inspect them without us guessing what they mean.
 */
export const CLASS = Object.freeze({
  IN: 1,
  CH: 3,
  HS: 4,
  NONE: 254,
  ANY: 255,
});

/**
 * QTYPE values that have a dedicated semantic mapping in the codec.
 * Stored separately from the numeric TYPE constants so that callers who only
 * care about record types don't accidentally reach for a pseudo-class.
 */
export const TYPE = Object.freeze({
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  OPT: 41,
  ANY: 255,
});

/** RCODE values carried in the header's lower byte (RFC 1035 §4.1.1, §6 §4.1.1). */
export const RCODE = Object.freeze({
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
});

/**
 * Read a big-endian unsigned 16-bit integer at `offset`.
 * Returns the value and the new cursor position so callers can chain reads
 * without bookkeeping intermediate offsets.
 */
function readU16(view, offset) {
  if (offset + 2 > view.byteLength) {
    throw new RangeError('truncated u16');
  }
  return { value: view.getUint16(offset), next: offset + 2 };
}

function readU32(view, offset) {
  if (offset + 4 > view.byteLength) {
    throw new RangeError('truncated u32');
  }
  return { value: view.getUint32(offset), next: offset + 4 };
}

/**
 * Parse a label sequence beginning at `offset`, following compression pointers
 * per RFC 1035 §4.1.4. A `visited` Set tracks pointer targets to defeat
 * malicious loops — a real threat when decoding untrusted data.
 *
 * Returns the decoded dot-separated name (without a trailing dot for the root)
 * and `end` — the offset just past the label sequence in the *original* stream
 * (i.e., not following the pointer). That distinction matters because callers
 * iterate question/answer records linearly and need the cursor to advance past
 * the first occurrence of the name, not the pointer target.
 */
function readName(view, u8, offset, visited) {
  const labels = [];
  let cursor = offset;
  let end = -1;
  let jumps = 0;
  const MAX_JUMPS = 128;

  for (;;) {
    if (cursor >= u8.length) {
      throw new RangeError('name runs past end of message');
    }
    const len = u8[cursor];
    if (len === 0) {
      cursor += 1;
      if (end === -1) end = cursor;
      break;
    }
    // Pointer: top two bits set. Follow once.
    if ((len & 0xc0) === 0xc0) {
      if (cursor + 2 > u8.length) {
        throw new RangeError('truncated compression pointer');
      }
      const ptr = ((len & 0x3f) << 8) | u8[cursor + 1];
      if (end === -1) end = cursor + 2;
      if (visited.has(ptr)) {
        throw new Error('name compression loop');
      }
      visited.add(ptr);
      cursor = ptr;
      jumps += 1;
      if (jumps > MAX_JUMPS) {
        throw new Error('too many compression jumps');
      }
      continue;
    }
    if ((len & 0xc0) !== 0) {
      throw new Error(`reserved label length bits: 0x${len.toString(16)}`);
    }
    cursor += 1;
    if (cursor + len > u8.length) {
      throw new RangeError('label runs past end of message');
    }
    labels.push(Buffer.from(u8.slice(cursor, cursor + len)).toString('latin1'));
    cursor += len;
  }
  const name = labels.join('.');
  return { name, end };
}

/**
 * Encode a domain name with simple run-length labels. We deliberately never
 * emit compression pointers: producing them correctly requires tracking
 * previously-written name offsets and matching suffixes, which adds complexity
 * for a marginal size win. Decoders must accept our uncompressed output.
 */
function writeName(u8, offset, name) {
  if (name === '' || name === '.') {
    if (offset + 1 > u8.length) throw new RangeError('no room for root label');
    u8[offset] = 0;
    return offset + 1;
  }
  let cursor = offset;
  for (const label of name.split('.')) {
    if (label.length === 0) {
      continue;
    }
    if (label.length > 63) {
      throw new Error(`label too long (${label.length} bytes)`);
    }
    if (cursor + 1 + label.length > u8.length) {
      throw new RangeError('no room for name');
    }
    u8[cursor] = label.length;
    cursor += 1;
    u8.set(Buffer.from(label, 'latin1'), cursor);
    cursor += label.length;
  }
  if (cursor + 1 > u8.length) {
    throw new RangeError('no room for terminator');
  }
  u8[cursor] = 0;
  return cursor + 1;
}

/** Read a question entry: QNAME, QTYPE, QCLASS (RFC 1035 §4.1.2). */
function readQuestion(view, u8, offset, visited) {
  const { name, end } = readName(view, u8, offset, visited);
  let cursor = end;
  const t = readU16(view, cursor); cursor = t.next;
  const c = readU16(view, cursor); cursor = c.next;
  return { record: { name, type: t.value, class: c.value }, next: cursor };
}

/**
 * Read a resource record (RFC 1035 §4.1.3). TTL is returned unsigned per spec;
 * callers that need signed arithmetic can interpret it themselves.
 */
function readRR(view, u8, offset, visited) {
  const { name, end } = readName(view, u8, offset, visited);
  let cursor = end;
  const t = readU16(view, cursor); cursor = t.next;
  const c = readU16(view, cursor); cursor = c.next;
  const ttl = readU32(view, cursor); cursor = ttl.next;
  const rdlen = readU16(view, cursor); cursor = rdlen.next;
  if (cursor + rdlen.value > u8.length) {
    throw new RangeError('RDATA runs past end of message');
  }
  const rdata = u8.slice(cursor, cursor + rdlen.value);
  cursor += rdlen.value;
  return {
    record: { name, type: t.value, class: c.value, ttl: ttl.value, rdata },
    next: cursor,
  };
}

/** Encode a 16-bit header word into the first two bytes of `bytes` at `off`. */
function writeHeaderFlag(bytes, off, qr, opcode, aa, tc, rd, ra, z, rcode) {
  const flag = ((qr & 1) << 15) | ((opcode & 0xf) << 11) | ((aa & 1) << 10) |
               ((tc & 1) << 9) | ((rd & 1) << 8) | ((ra & 1) << 7) |
               ((z & 7) << 4) | (rcode & 0xf);
  bytes[off] = (flag >> 8) & 0xff;
  bytes[off + 1] = flag & 0xff;
}

/**
 * Decode a DNS message from a Uint8Array (or Buffer). Returns a structured
 * object; RDATA is left raw so callers can interpret A, AAAA, MX, etc. per
 * their own needs. We do not invent semantic types we don't actually parse.
 */
export function decode(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  if (u8.length < 12) {
    throw new Error('message too short for DNS header');
  }
  const id = view.getUint16(0);
  const flagWord = view.getUint16(2);
  const qr = (flagWord >> 15) & 1;
  const opcode = (flagWord >> 11) & 0xf;
  const aa = (flagWord >> 10) & 1;
  const tc = (flagWord >> 9) & 1;
  const rd = (flagWord >> 8) & 1;
  const ra = (flagWord >> 7) & 1;
  const z = (flagWord >> 4) & 7;
  const rcode = flagWord & 0xf;
  const qdcount = view.getUint16(4);
  const ancount = view.getUint16(6);
  const nscount = view.getUint16(8);
  const arcount = view.getUint16(10);

  let cursor = 12;
  const visited = new Set();
  const questions = [];
  for (let i = 0; i < qdcount; i++) {
    const r = readQuestion(view, u8, cursor, visited);
    questions.push(r.record);
    cursor = r.next;
  }
  const answers = [];
  for (let i = 0; i < ancount; i++) {
    const r = readRR(view, u8, cursor, visited);
    answers.push(r.record);
    cursor = r.next;
  }
  const authority = [];
  for (let i = 0; i < nscount; i++) {
    const r = readRR(view, u8, cursor, visited);
    authority.push(r.record);
    cursor = r.next;
  }
  const additional = [];
  for (let i = 0; i < arcount; i++) {
    const r = readRR(view, u8, cursor, visited);
    additional.push(r.record);
    cursor = r.next;
  }

  return {
    header: {
      id, qr, opcode, aa, tc, rd, ra, z, rcode,
      qdcount, ancount, nscount, arcount,
    },
    question: questions,
    answer: answers,
    authority,
    additional,
  };
}

/**
 * Encode a structured message back into wire format. The `question`,
 * `answer`, `authority`, `additional` arrays accept plain objects. For records,
 * `rdata` may be a Uint8Array or Buffer. `z` defaults to 0 (reserved, must be
 * zero on transmit per RFC 1035 §4.1.1).
 */
export function encode(msg) {
  const header = msg.header || {};
  const questions = msg.question || [];
  const answers = msg.answer || [];
  const authority = msg.authority || [];
  const additional = msg.additional || [];

  const rrs = [...answers, ...authority, ...additional];
  const buf = Buffer.alloc(8192);
  const u8 = new Uint8Array(buf.buffer, buf.byteOffset, buf.length);

  const id = header.id != null ? header.id : 0;
  u8[0] = (id >> 8) & 0xff;
  u8[1] = id & 0xff;
  writeHeaderFlag(
    u8, 2,
    header.qr || 0,
    header.opcode || 0,
    header.aa || 0,
    header.tc || 0,
    header.rd || 0,
    header.ra || 0,
    header.z || 0,
    header.rcode || 0
  );

  const view = new DataView(u8.buffer, u8.byteOffset, u8.length);
  view.setUint16(4, questions.length);
  view.setUint16(6, answers.length);
  view.setUint16(8, authority.length);
  view.setUint16(10, additional.length);

  let offset = 12;
  for (const q of questions) {
    offset = writeName(u8, offset, q.name || '');
    view.setUint16(offset, q.type); offset += 2;
    view.setUint16(offset, q.class); offset += 2;
  }
  for (const r of rrs) {
    offset = writeName(u8, offset, r.name || '');
    view.setUint16(offset, r.type); offset += 2;
    view.setUint16(offset, r.class); offset += 2;
    view.setUint32(offset, r.ttl != null ? r.ttl : 0); offset += 4;
    const rdata = r.rdata instanceof Uint8Array ? r.rdata : Buffer.from(r.rdata || []);
    view.setUint16(offset, rdata.length); offset += 2;
    u8.set(rdata, offset); offset += rdata.length;
  }
  return Buffer.from(u8.buffer, u8.byteOffset, offset);
}
