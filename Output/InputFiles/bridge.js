// src/tool-pack.ts
function isDynamicPack(pack) {
  return pack.kind === "dynamic";
}
function ok(data) {
  return {
    content: [{ type: "text", text: JSON.stringify(data) }],
    structuredContent: data
  };
}
function customResult(result) {
  return result;
}
function errorResult(message) {
  return {
    content: [{ type: "text", text: message }],
    isError: true
  };
}

// src/bridge/registry.ts
function parsePackList(raw) {
  if (raw === void 0) return null;
  return raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
}
var DEFAULT_MCP_URL = "/mcp";
function normalizeMcpUrl(raw) {
  const v = (raw ?? "").trim();
  if (v.toLowerCase() === "none") return void 0;
  if (v === "") {
    console.warn(
      `[webmcp-interceptor] No data-mcp-url configured; defaulting to /mcp. This probes a same-origin endpoint with the user's session credentials. Set data-mcp-url="none" to opt out, or specify the endpoint explicitly.`
    );
    return DEFAULT_MCP_URL;
  }
  return v;
}
function selectActivePacks(all, requested, defaults) {
  const names = requested ?? defaults;
  const byName = new Map(all.map((p) => [p.name, p]));
  const active = [];
  for (const name of names) {
    const pack = byName.get(name);
    if (pack) active.push(pack);
    else
      console.warn(
        `[webmcp-interceptor] Requested pack "${name}" is not bundled; skipping.`
      );
  }
  return active;
}
function resolveStaticPacks(packs) {
  const resolved = [];
  for (const pack of packs) {
    if (!isDynamicPack(pack)) {
      resolved.push({
        name: pack.name,
        tools: pack.tools,
        handlers: pack.handlers,
        dynamic: false
      });
    }
  }
  return resolved;
}
async function resolveDynamicPacks(packs, ctx) {
  const dynamics = packs.filter(isDynamicPack);
  return Promise.all(
    dynamics.map(async (pack) => {
      try {
        const { tools, handlers } = await pack.resolve(ctx);
        return { name: pack.name, tools, handlers, dynamic: true };
      } catch (err) {
        console.warn(
          `[webmcp-interceptor] Dynamic pack "${pack.name}" failed to resolve; skipping.`,
          err
        );
        return { name: pack.name, tools: [], handlers: {}, dynamic: true };
      }
    })
  );
}
var MAX_TOTAL_TOOLS = 200;
function buildRegistry(packs) {
  const tools = [];
  const handlers = {};
  const seen = /* @__PURE__ */ new Map();
  for (const pack of packs) {
    const toolNames = new Set(pack.tools.map((t) => t.name));
    for (const tool of pack.tools) {
      if (!pack.handlers[tool.name]) {
        throw new Error(
          `Tool-pack "${pack.name}" declares tool "${tool.name}" but has no matching handler.`
        );
      }
    }
    for (const name of Object.keys(pack.handlers)) {
      if (!toolNames.has(name)) {
        throw new Error(
          `Tool-pack "${pack.name}" has a handler for "${name}" with no matching tool descriptor.`
        );
      }
    }
    for (const tool of pack.tools) {
      const existing = seen.get(tool.name);
      if (existing) {
        if (pack.dynamic) {
          console.warn(
            `[webmcp-interceptor] Tool "${tool.name}" from dynamic pack "${pack.name}" collides with "${existing}"; skipping the dynamic one.`
          );
          continue;
        }
        throw new Error(
          `Tool name collision: "${tool.name}" registered by both "${existing}" and "${pack.name}".`
        );
      }
      if (tools.length >= MAX_TOTAL_TOOLS) {
        console.warn(
          `[webmcp-interceptor] Reached ${MAX_TOTAL_TOOLS}-tool cap; skipping remaining tools from "${pack.name}".`
        );
        return { tools, handlers };
      }
      const handler = pack.handlers[tool.name];
      if (!handler) {
        throw new Error(
          `Tool-pack "${pack.name}" declares tool "${tool.name}" but has no matching handler.`
        );
      }
      seen.set(tool.name, pack.name);
      tools.push(tool);
      handlers[tool.name] = handler;
    }
  }
  return { tools, handlers };
}

// src/bridge/packs/c2pa/cbor.ts
var BREAK = 255;
var textDecoder = new TextDecoder("utf-8", { fatal: false });
var MAX_ITEMS = 1e6;
var MAX_INDEFINITE_BYTES = 16 * 1024 * 1024;
function decodeCbor(bytes) {
  return new CborDecoder(bytes).decode();
}
function isCborTag(v) {
  return typeof v === "object" && v !== null && !(v instanceof Uint8Array) && !Array.isArray(v) && !(v instanceof Map) && "tag" in v;
}
function isCborSimple(v) {
  return typeof v === "object" && v !== null && !(v instanceof Uint8Array) && !Array.isArray(v) && !(v instanceof Map) && "simple" in v;
}
var CborDecoder = class {
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  bytes;
  view;
  off = 0;
  itemCount = 0;
  decode() {
    return this.readValue(0);
  }
  /** Read one item. `depth` guards against pathological nesting. */
  readValue(depth) {
    if (depth > 256) throw new Error("CBOR nesting too deep");
    if (++this.itemCount > MAX_ITEMS) throw new Error("CBOR item count exceeds budget");
    const ib = this.u8();
    const major = ib >> 5;
    const ai = ib & 31;
    switch (major) {
      case 0:
        return this.readUint(ai);
      case 1: {
        const n = this.readUint(ai);
        return typeof n === "bigint" ? -1n - n : -1 - n;
      }
      case 2:
        return this.readByteString(ai, depth, 2);
      case 3:
        return textDecoder.decode(this.readByteString(ai, depth, 3));
      case 4:
        return this.readArray(ai, depth);
      case 5:
        return this.readMap(ai, depth);
      case 6: {
        const tag = this.asLength(this.readUint(ai));
        return { tag, value: this.readValue(depth + 1) };
      }
      default:
        return this.readSimple(ai);
    }
  }
  /** Read the argument that follows the initial byte (major 0/1/6). */
  readUint(ai) {
    if (ai < 24) return ai;
    if (ai === 24) return this.u8();
    if (ai === 25) {
      const v = this.view.getUint16(this.off);
      this.off += 2;
      return v;
    }
    if (ai === 26) {
      const v = this.view.getUint32(this.off);
      this.off += 4;
      return v;
    }
    if (ai === 27) {
      const v = this.view.getBigUint64(this.off);
      this.off += 8;
      return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
    }
    throw new Error(`Invalid CBOR additional-info value: ${ai}`);
  }
  readByteString(ai, depth, majorType) {
    if (ai === 31) {
      const chunks = [];
      let total = 0;
      for (; ; ) {
        const ib = this.peek();
        if (ib === BREAK) {
          this.off += 1;
          break;
        }
        const major = ib >> 5;
        const chunkAi = ib & 31;
        if (major !== majorType || chunkAi === 31) {
          throw new Error("Indefinite-length string chunk must be a definite-length string of the same type");
        }
        this.off += 1;
        if (++this.itemCount > MAX_ITEMS) throw new Error("CBOR item count exceeds budget");
        const chunk = this.readByteString(chunkAi, depth + 1, majorType);
        chunks.push(chunk);
        total += chunk.length;
        if (total > MAX_INDEFINITE_BYTES) {
          throw new Error("Indefinite-length string exceeds size limit");
        }
      }
      const out2 = new Uint8Array(total);
      let p = 0;
      for (const c of chunks) {
        out2.set(c, p);
        p += c.length;
      }
      return out2;
    }
    const len = this.asLength(this.readUint(ai));
    const end = this.off + len;
    if (end > this.bytes.length) throw new Error("CBOR byte string truncated");
    const out = this.bytes.subarray(this.off, end);
    this.off = end;
    return out;
  }
  readArray(ai, depth) {
    const out = [];
    if (ai === 31) {
      while (this.peek() !== BREAK) out.push(this.readValue(depth + 1));
      this.off += 1;
      return out;
    }
    const len = this.asLength(this.readUint(ai));
    for (let i = 0; i < len; i++) out.push(this.readValue(depth + 1));
    return out;
  }
  readMap(ai, depth) {
    const out = /* @__PURE__ */ new Map();
    if (ai === 31) {
      while (this.peek() !== BREAK) {
        const k = this.readValue(depth + 1);
        out.set(k, this.readValue(depth + 1));
      }
      this.off += 1;
      return out;
    }
    const len = this.asLength(this.readUint(ai));
    for (let i = 0; i < len; i++) {
      const k = this.readValue(depth + 1);
      out.set(k, this.readValue(depth + 1));
    }
    return out;
  }
  readSimple(ai) {
    switch (ai) {
      case 20:
        return false;
      case 21:
        return true;
      case 22:
        return null;
      case 23:
        return void 0;
      case 24:
        return { simple: this.u8() };
      // one-byte simple value (32-255)
      case 25:
        return this.readHalfFloat();
      case 26: {
        const v = this.view.getFloat32(this.off);
        this.off += 4;
        return v;
      }
      case 27: {
        const v = this.view.getFloat64(this.off);
        this.off += 8;
        return v;
      }
      default:
        return { simple: ai };
    }
  }
  /** IEEE 754 half-precision (binary16) → JS number. */
  readHalfFloat() {
    const half = this.view.getUint16(this.off);
    this.off += 2;
    const exp = (half & 31744) >> 10;
    const frac = half & 1023;
    const sign = half & 32768 ? -1 : 1;
    if (exp === 0) return sign * 2 ** -14 * (frac / 1024);
    if (exp === 31) return frac ? NaN : sign * Infinity;
    return sign * 2 ** (exp - 15) * (1 + frac / 1024);
  }
  u8() {
    if (this.off >= this.bytes.length) throw new Error("CBOR truncated");
    const v = this.view.getUint8(this.off);
    this.off += 1;
    return v;
  }
  peek() {
    if (this.off >= this.bytes.length) throw new Error("CBOR truncated");
    return this.view.getUint8(this.off);
  }
  /** Coerce a length/tag argument to a sane JS number or throw. */
  asLength(v) {
    if (typeof v === "bigint" || v > 2147483647) {
      throw new Error("CBOR length/tag exceeds supported range");
    }
    return v;
  }
};

// src/bridge/packs/c2pa/x509.ts
var textDecoder2 = new TextDecoder("utf-8", { fatal: false });
var OID_COMMON_NAME = [85, 4, 3];
function parseCertificate(der) {
  try {
    return parseCertificateUnsafe(der);
  } catch {
    return {};
  }
}
function parseCertificateUnsafe(der) {
  const view = new DataView(der.buffer, der.byteOffset, der.byteLength);
  const cert = readTlv(view, 0, der.length);
  if (!cert) return {};
  const tbs = readTlv(view, cert.contentStart, cert.contentEnd);
  if (!tbs) return {};
  const fields = readChildren(view, der, tbs.contentStart, tbs.contentEnd);
  let i = 0;
  if (fields[i] && fields[i]?.tag === 160) i += 1;
  const issuer = fields[i + 2];
  const validity = fields[i + 3];
  const subject = fields[i + 4];
  const info = {};
  if (issuer) info.issuerCN = extractCommonName(view, der, issuer);
  if (subject) info.subjectCN = extractCommonName(view, der, subject);
  if (validity) {
    const times = readChildren(view, der, validity.contentStart, validity.contentEnd);
    if (times[0]) info.notBefore = parseTime(der, times[0]);
    if (times[1]) info.notAfter = parseTime(der, times[1]);
  }
  return info;
}
function readTlv(view, off, limit) {
  if (off + 2 > limit) return null;
  const tag = view.getUint8(off);
  let p = off + 1;
  let len = view.getUint8(p);
  p += 1;
  if (len & 128) {
    const n = len & 127;
    if (n === 0 || n > 4) return null;
    len = 0;
    for (let i = 0; i < n; i++) {
      len = len << 8 | view.getUint8(p);
      p += 1;
    }
  }
  const contentStart = p;
  const contentEnd = p + len;
  if (contentEnd > limit) return null;
  return { tag, contentStart, contentEnd, end: contentEnd };
}
function readChildren(view, bytes, start, end) {
  const out = [];
  let off = start;
  while (off < end) {
    const node = readTlv(view, off, end);
    if (!node) break;
    out.push(node);
    off = node.end;
  }
  return out;
}
function extractCommonName(view, bytes, name) {
  for (const rdn of readChildren(view, bytes, name.contentStart, name.contentEnd)) {
    for (const atv of readChildren(view, bytes, rdn.contentStart, rdn.contentEnd)) {
      const parts = readChildren(view, bytes, atv.contentStart, atv.contentEnd);
      const oid = parts[0];
      const value = parts[1];
      if (oid && value && oid.tag === 6 && oidEquals(bytes, oid, OID_COMMON_NAME)) {
        return textDecoder2.decode(bytes.subarray(value.contentStart, value.contentEnd));
      }
    }
  }
  return void 0;
}
function oidEquals(bytes, node, expected) {
  const len = node.contentEnd - node.contentStart;
  if (len !== expected.length) return false;
  for (let i = 0; i < len; i++) {
    if (bytes[node.contentStart + i] !== expected[i]) return false;
  }
  return true;
}
function parseTime(bytes, node) {
  const raw = textDecoder2.decode(bytes.subarray(node.contentStart, node.contentEnd));
  const isUtc = node.tag === 23;
  const m = isUtc ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/.exec(raw) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z?$/.exec(raw);
  if (!m) return raw;
  let year = Number(m[1]);
  if (isUtc) year += year < 50 ? 2e3 : 1900;
  const iso = `${pad(year, 4)}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? "00"}Z`;
  return iso;
}
function pad(n, width) {
  return String(n).padStart(width, "0");
}

// src/bridge/packs/c2pa/manifest.ts
function buildManifestStore(store) {
  const manifests = store.children.map(decodeManifest);
  const active = manifests[manifests.length - 1];
  const result = {
    manifestCount: manifests.length,
    manifests
  };
  if (store.label !== void 0) result.label = store.label;
  if (active?.label !== void 0) result.activeManifestLabel = active.label;
  return result;
}
function decodeManifest(node) {
  let claimNode;
  let signatureNode;
  let assertionStore;
  for (const child of node.children) {
    const label = child.label ?? "";
    if (label.startsWith("c2pa.claim") || child.contentType === "c2cl") {
      claimNode = child;
    } else if (label === "c2pa.signature" || child.contentType === "c2cs") {
      signatureNode = child;
    } else if (label === "c2pa.assertions" || child.contentType === "c2as") {
      assertionStore = child;
    }
  }
  const assertions = assertionStore ? assertionStore.children.map(decodeAssertion) : [];
  const manifest = { assertions };
  if (node.label !== void 0) manifest.label = node.label;
  if (claimNode?.cbor !== void 0) {
    const claim = cborToJson(claimNode.cbor);
    if (claim !== null && typeof claim === "object" && !Array.isArray(claim)) {
      manifest.claim = claim;
    }
  }
  if (signatureNode?.cbor !== void 0) {
    manifest.signature = decodeCoseSignature(signatureNode.cbor);
  }
  return manifest;
}
function decodeAssertion(node) {
  const out = {};
  if (node.label !== void 0) out.label = node.label;
  if (node.cbor !== void 0) {
    out.data = cborToJson(node.cbor);
  } else if (node.json !== void 0) {
    out.data = node.json;
  } else if (node.binary !== void 0) {
    out.binary = node.binary;
  }
  return out;
}
var COSE_ALG = {
  [-7]: "ES256",
  [-35]: "ES384",
  [-36]: "ES512",
  [-8]: "EdDSA",
  [-37]: "PS256",
  [-38]: "PS384",
  [-39]: "PS512",
  [-257]: "RS256",
  [-258]: "RS384",
  [-259]: "RS512"
};
function decodeCoseSignature(cose) {
  const arr = isCborTag(cose) ? cose.value : cose;
  if (!Array.isArray(arr) || arr.length < 4) return {};
  const protectedHeader = decodeProtectedHeader(arr[0]);
  const unprotected = arr[1] instanceof Map ? arr[1] : /* @__PURE__ */ new Map();
  const sig = {};
  const algId = asInt(protectedHeader.get(1) ?? unprotected.get(1));
  if (algId !== void 0) sig.alg = COSE_ALG[algId] ?? `COSE(${algId})`;
  const certs = readX5Chain(protectedHeader.get(33) ?? unprotected.get(33));
  if (certs.length > 0) {
    sig.certChainLength = certs.length;
    const first = certs[0];
    if (first) {
      const info = parseCertificate(first);
      if (info.subjectCN !== void 0) sig.signedBy = info.subjectCN;
      if (info.issuerCN !== void 0) sig.certifiedBy = info.issuerCN;
      if (info.notBefore !== void 0) sig.certValidFrom = info.notBefore;
      if (info.notAfter !== void 0) sig.certValidTo = info.notAfter;
    }
  }
  return sig;
}
function decodeProtectedHeader(value) {
  if (value instanceof Uint8Array && value.length > 0) {
    const decoded = decodeCbor(value);
    if (decoded instanceof Map) return decoded;
  }
  return /* @__PURE__ */ new Map();
}
function readX5Chain(value) {
  if (value instanceof Uint8Array) return [value];
  if (Array.isArray(value)) {
    return value.filter((c) => c instanceof Uint8Array);
  }
  return [];
}
function asInt(value) {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "bigint") return Number(value);
  return void 0;
}
var MAX_INLINE_BYTES = 64;
function cborToJson(value) {
  if (value === null || value === void 0) return value ?? null;
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Uint8Array) return bytesToJson(value);
  if (Array.isArray(value)) return value.map(cborToJson);
  if (value instanceof Map) {
    const obj = /* @__PURE__ */ Object.create(null);
    for (const [k, v] of value) obj[keyToString(k)] = cborToJson(v);
    return obj;
  }
  if (isCborTag(value)) {
    return { $tag: value.tag, value: cborToJson(value.value) };
  }
  if (isCborSimple(value)) {
    return { $simple: value.simple };
  }
  return value;
}
function bytesToJson(b) {
  if (b.length <= MAX_INLINE_BYTES) return { $bytes: b.length, hex: toHex(b) };
  return { $bytes: b.length, hex: `${toHex(b.subarray(0, 32))}\u2026` };
}
function keyToString(k) {
  if (typeof k === "string") return k;
  if (typeof k === "number" || typeof k === "bigint" || typeof k === "boolean") {
    return String(k);
  }
  return JSON.stringify(cborToJson(k));
}
function toHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const byte = b[i];
    if (byte === void 0) break;
    s += byte.toString(16).padStart(2, "0");
  }
  return s;
}

// src/bridge/packs/c2pa/jumbf.ts
var textDecoder3 = new TextDecoder("utf-8", { fatal: false });
var MAX_JUMBF_BOXES = 1e4;
var MAX_APP11_PACKETS = 1024;
var MAX_FRAGMENTS_PER_INSTANCE = 256;
function detectImageFormat(bytes) {
  if (bytes.length >= 3 && bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) {
    return "jpeg";
  }
  if (bytes.length >= 8 && bytes[0] === 137 && bytes[1] === 80 && bytes[2] === 78 && bytes[3] === 71 && bytes[4] === 13 && bytes[5] === 10 && bytes[6] === 26 && bytes[7] === 10) {
    return "png";
  }
  return "unknown";
}
function extractC2paJumbf(bytes) {
  switch (detectImageFormat(bytes)) {
    case "jpeg":
      return extractFromJpeg(bytes);
    case "png":
      return extractFromPng(bytes);
    default:
      return null;
  }
}
function parseManifestStore(jumbf) {
  const view = new DataView(jumbf.buffer, jumbf.byteOffset, jumbf.byteLength);
  const top = readBox(view, jumbf, 0, jumbf.length);
  if (!top || top.type !== "jumb") return null;
  return parseSuperbox(view, jumbf, top.payloadStart, top.payloadEnd, 0, {
    count: 0
  });
}
function extractFromJpeg(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(0) !== 65496) return null;
  const packets = /* @__PURE__ */ new Map();
  let app11Count = 0;
  let off = 2;
  while (off + 2 <= bytes.length) {
    if (view.getUint8(off) !== 255) break;
    let marker = view.getUint8(off + 1);
    while (marker === 255 && off + 2 < bytes.length) {
      off += 1;
      marker = view.getUint8(off + 1);
    }
    off += 2;
    if (marker === 217 || marker === 218) break;
    if (marker === 1 || marker >= 208 && marker <= 215) continue;
    if (off + 2 > bytes.length) break;
    const segLen = view.getUint16(off);
    const segStart = off + 2;
    const segEnd = off + segLen;
    if (segLen < 2 || segEnd > bytes.length) break;
    if (marker === 235 && segEnd - segStart >= 8) {
      if (view.getUint16(segStart) === 19024) {
        if (++app11Count > MAX_APP11_PACKETS) break;
        const en = view.getUint16(segStart + 2);
        const z = view.getUint32(segStart + 4);
        const data = bytes.subarray(segStart + 8, segEnd);
        const arr = packets.get(en) ?? [];
        if (arr.length < MAX_FRAGMENTS_PER_INSTANCE) {
          arr.push({ z, data });
          packets.set(en, arr);
        }
      }
    }
    off = segEnd;
  }
  for (const arr of packets.values()) {
    arr.sort((a, b) => a.z - b.z);
    const first = arr[0];
    if (!first) continue;
    let headerLen = 8;
    if (first.data.length >= 4) {
      const fv = new DataView(
        first.data.buffer,
        first.data.byteOffset,
        first.data.byteLength
      );
      if (fv.getUint32(0) === 1) headerLen = 16;
    }
    const pieces = [];
    let total = 0;
    for (let i = 0; i < arr.length; i++) {
      const pk = arr[i];
      if (!pk) continue;
      const piece = i === 0 ? pk.data : pk.data.subarray(headerLen);
      pieces.push(piece);
      total += piece.length;
    }
    const buf = new Uint8Array(total);
    let p = 0;
    for (const piece of pieces) {
      buf.set(piece, p);
      p += piece.length;
    }
    if (isC2paStore(buf)) return buf;
  }
  return null;
}
function extractFromPng(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let off = 8;
  while (off + 8 <= bytes.length) {
    const len = view.getUint32(off);
    const type = ascii(bytes, off + 4, 4);
    const dataStart = off + 8;
    const dataEnd = dataStart + len;
    if (dataEnd + 4 > bytes.length) break;
    if (type === "caBX") {
      const buf = bytes.subarray(dataStart, dataEnd);
      return isC2paStore(buf) ? buf : null;
    }
    if (type === "IEND") break;
    off = dataEnd + 4;
  }
  return null;
}
function readBox(view, bytes, offset, limit) {
  if (offset + 8 > limit) return null;
  let len = view.getUint32(offset);
  const type = ascii(bytes, offset + 4, 4);
  let headerLen = 8;
  if (len === 1) {
    if (offset + 16 > limit) return null;
    const hi = view.getUint32(offset + 8);
    const lo = view.getUint32(offset + 12);
    len = hi * 4294967296 + lo;
    headerLen = 16;
  } else if (len === 0) {
    len = limit - offset;
  }
  const boxEnd = offset + len;
  if (len < headerLen || boxEnd > limit) return null;
  return { type, payloadStart: offset + headerLen, payloadEnd: boxEnd, boxEnd };
}
function parseSuperbox(view, bytes, start, end, depth, counter) {
  const node = { contentType: "", children: [] };
  if (depth > 64) return node;
  let off = start;
  const first = readBox(view, bytes, off, end);
  if (first && first.type === "jumd") {
    if (++counter.count > MAX_JUMBF_BOXES) return node;
    parseDescription(view, bytes, first.payloadStart, first.payloadEnd, node);
    off = first.boxEnd;
  }
  while (off < end) {
    if (++counter.count > MAX_JUMBF_BOXES) return node;
    const box = readBox(view, bytes, off, end);
    if (!box) break;
    switch (box.type) {
      case "jumb":
        node.children.push(
          parseSuperbox(view, bytes, box.payloadStart, box.payloadEnd, depth + 1, counter)
        );
        break;
      case "cbor":
        try {
          node.cbor = decodeCbor(bytes.subarray(box.payloadStart, box.payloadEnd));
        } catch {
        }
        break;
      case "json":
        try {
          node.json = JSON.parse(
            textDecoder3.decode(bytes.subarray(box.payloadStart, box.payloadEnd))
          );
        } catch {
        }
        break;
      case "bidb":
      // embedded-file data box
      case "uuid":
        node.binary = { size: box.payloadEnd - box.payloadStart };
        break;
      default:
        break;
    }
    off = box.boxEnd;
  }
  return node;
}
function parseDescription(view, bytes, start, end, node) {
  if (start + 17 > end) return;
  node.contentType = ascii(bytes, start, 4);
  const toggles = view.getUint8(start + 16);
  let off = start + 17;
  if (toggles & 2) {
    let z = off;
    while (z < end && view.getUint8(z) !== 0) z += 1;
    node.label = textDecoder3.decode(bytes.subarray(off, z));
  }
}
function isC2paStore(buf) {
  if (buf.length < 16) return false;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const top = readBox(view, buf, 0, buf.length);
  if (!top || top.type !== "jumb") return false;
  const desc = readBox(view, buf, top.payloadStart, top.payloadEnd);
  if (!desc || desc.type !== "jumd") return false;
  return ascii(buf, desc.payloadStart, 4) === "c2pa";
}
function ascii(bytes, off, len) {
  let s = "";
  for (let i = 0; i < len; i++) {
    const c = bytes[off + i];
    if (c === void 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

// src/bridge/packs/c2pa/c2pa-executor.ts
var MAX_SCAN_IMAGES = 100;
var MAX_IMAGE_BYTES = 64 * 1024 * 1024;
var FETCH_TIMEOUT_MS = 15e3;
var SCAN_CONCURRENCY = 6;
var SCAN_BUDGET_MS = 3e4;
var NO_VERIFICATION_NOTE = "Manifest decoded only. Cryptographic signature, certificate-chain, and trust-list verification were NOT performed; treat provenance as unverified claims.";
async function scanImages(limit, signal) {
  const allSources = collectImageSources();
  const capped = Math.min(limit, MAX_SCAN_IMAGES);
  const sources = allSources.slice(0, capped);
  const deadline = anySignal(signal, AbortSignal.timeout(SCAN_BUDGET_MS));
  const results = await mapWithConcurrency(
    sources,
    SCAN_CONCURRENCY,
    (src) => scanOne(src, deadline)
  );
  const withC2pa = results.filter((r) => r.hasC2pa).length;
  return {
    imageCount: allSources.length,
    scanned: results.length,
    withC2pa,
    results
  };
}
async function scanOne(src, signal) {
  try {
    const bytes = await fetchImageBytes(src, signal);
    const analysis = analyzeBytes(bytes);
    if (!analysis.store) {
      return { src, hasC2pa: false, format: analysis.format };
    }
    const active = activeManifest(analysis.store);
    const summary = {
      src,
      hasC2pa: true,
      format: analysis.format,
      manifestCount: analysis.store.manifestCount,
      signatureVerified: false
    };
    const claimGenerator = readClaimGenerator(active?.claim);
    const title = readTitle(active?.claim);
    if (claimGenerator !== void 0) summary.claimGenerator = claimGenerator;
    if (title !== void 0) summary.title = title;
    if (active?.signature?.signedBy !== void 0) {
      summary.signedBy = active.signature.signedBy;
    }
    return summary;
  } catch (err) {
    return { src, hasC2pa: false, error: errorMessage(err) };
  }
}
async function inspectImage(opts, signal) {
  const isUrlMode = Boolean(opts.url);
  const src = resolveSource(opts);
  const bytes = await fetchImageBytes(src, signal, isUrlMode);
  const analysis = analyzeBytes(bytes);
  if (!analysis.store) {
    return {
      src,
      hasC2pa: false,
      format: analysis.format,
      message: analysis.format === "unknown" ? "Unsupported image format (only JPEG and PNG are parsed today)." : "No C2PA manifest found in this image."
    };
  }
  return {
    src,
    hasC2pa: true,
    format: analysis.format,
    manifestStore: analysis.store,
    validation: { signatureVerified: false, note: NO_VERIFICATION_NOTE }
  };
}
function analyzeBytes(bytes) {
  const format = detectImageFormat(bytes);
  const jumbf = extractC2paJumbf(bytes);
  if (!jumbf) return { format };
  const tree = parseManifestStore(jumbf);
  if (!tree) return { format };
  return { format, store: buildManifestStore(tree) };
}
function collectImageSources() {
  const seen = /* @__PURE__ */ new Set();
  const out = [];
  for (const img of Array.from(document.querySelectorAll("img"))) {
    const el = img;
    const src = el.currentSrc || el.src;
    if (src && !seen.has(src)) {
      seen.add(src);
      out.push(src);
    }
  }
  return out;
}
function resolveSource(opts) {
  if (opts.url) {
    const resolved = new URL(opts.url, document.location.href);
    if (resolved.origin !== document.location.origin) {
      throw new Error("URL must be same-origin.");
    }
    return resolved.toString();
  }
  if (opts.selector) {
    const el = document.querySelector(opts.selector);
    if (!el) throw new Error(`No element matches selector: ${opts.selector}`);
    if (!(el instanceof HTMLImageElement)) {
      throw new Error(`Element is not an <img>: ${opts.selector}`);
    }
    const src = el.currentSrc || el.src;
    if (!src) throw new Error(`<img> has no resolved src: ${opts.selector}`);
    return src;
  }
  throw new Error("Provide either a `selector` or a `url`.");
}
async function fetchImageBytes(src, signal, noRedirect = false) {
  const combined = anySignal(signal, AbortSignal.timeout(FETCH_TIMEOUT_MS));
  let res;
  try {
    res = await fetch(src, {
      signal: combined,
      // Only block redirects when the agent supplied the URL.
      // Scan/selector mode fetches already-resolved currentSrc URLs.
      ...noRedirect ? { redirect: "error" } : {}
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "TimeoutError") {
      throw new Error("Image fetch timed out");
    }
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new Error("Image fetch aborted");
    }
    throw err;
  }
  if (!res.ok) throw new Error("Image fetch failed.");
  const length = Number(res.headers.get("content-length") ?? "0");
  if (length > MAX_IMAGE_BYTES) {
    throw new Error(`Image too large to inspect (${length} bytes)`);
  }
  if (!res.body) throw new Error("Response has no body stream");
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_IMAGE_BYTES) {
      await reader.cancel();
      throw new Error(`Image too large to inspect (${total} bytes)`);
    }
    chunks.push(value);
  }
  const assembled = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    assembled.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return assembled;
}
function activeManifest(store) {
  return store.manifests[store.manifests.length - 1];
}
function readClaimGenerator(claim) {
  if (!claim) return void 0;
  const info = claim["claim_generator_info"];
  if (Array.isArray(info) && info.length > 0) {
    const first = info[0];
    if (first && typeof first === "object") {
      const name = first["name"];
      const version = first["version"];
      if (typeof name === "string") {
        return typeof version === "string" ? `${name} ${version}` : name;
      }
    }
  }
  const generator = claim["claim_generator"];
  return typeof generator === "string" ? generator : void 0;
}
function readTitle(claim) {
  if (!claim) return void 0;
  const title = claim["dc:title"] ?? claim["title"];
  return typeof title === "string" ? title : void 0;
}
function errorMessage(err) {
  return err instanceof Error ? err.message : String(err);
}
function anySignal(optional, required) {
  return optional ? AbortSignal.any([optional, required]) : required;
}
async function mapWithConcurrency(items, concurrency, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = [];
  const limit = Math.max(1, Math.min(concurrency, items.length));
  for (let w = 0; w < limit; w++) {
    workers.push(
      (async () => {
        for (; ; ) {
          const i = next++;
          if (i >= items.length) return;
          const item = items[i];
          if (item === void 0) continue;
          results[i] = await fn(item);
        }
      })()
    );
  }
  await Promise.all(workers);
  return results;
}

// src/bridge/packs/c2pa/index.ts
var TOOLS = [
  {
    name: "scan_images_c2pa",
    description: "Scan every <img> on the current page for C2PA Content Credentials (content provenance metadata) and return a per-image summary: whether a manifest is present, the claim generator (the tool that produced or edited the image), the title, and the signer name. Use this to find which images on a page carry provenance data. Note: provenance is decoded but NOT cryptographically verified.",
    inputSchema: {
      type: "object",
      properties: {
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 25,
          description: "Maximum number of images to fetch and scan (default 25, max 100)."
        }
      },
      required: []
    }
  },
  {
    name: "inspect_image_c2pa",
    description: "Fetch a single image (by CSS selector or URL) and return its fully decoded C2PA manifest store: every manifest's claim, assertions (e.g. c2pa.actions edit history, schema.org authorship), and the COSE signature details (algorithm and signing-certificate identity). Provide exactly one of `selector` or `url`. Note: the signature is decoded but NOT cryptographically verified.",
    inputSchema: {
      type: "object",
      properties: {
        selector: {
          type: "string",
          maxLength: 8192,
          description: "CSS selector for an <img> element on the page."
        },
        url: {
          type: "string",
          maxLength: 8192,
          description: "Same-origin image URL (absolute same-origin, or relative to the current page) to fetch and inspect. Cross-origin URLs are rejected."
        }
      },
      required: []
    }
  }
];
function optionalInt(args, key, min, max, fallback) {
  if (typeof args !== "object" || args === null) return fallback;
  const v = args[key];
  if (v === void 0) return fallback;
  if (typeof v !== "number" || !Number.isInteger(v)) return null;
  if (v < min || v > max) return null;
  return v;
}
var MAX_STRING_ARG = 8192;
function readStringArg(args, key) {
  if (typeof args !== "object" || args === null) return { kind: "absent" };
  const v = args[key];
  if (v === void 0 || v === null) return { kind: "absent" };
  if (typeof v !== "string") {
    return { kind: "invalid", reason: `\`${key}\` must be a string.` };
  }
  if (v.length === 0) return { kind: "absent" };
  if (v.length > MAX_STRING_ARG) {
    return {
      kind: "invalid",
      reason: `\`${key}\` exceeds the ${MAX_STRING_ARG}-character limit.`
    };
  }
  return { kind: "ok", value: v };
}
var handleScanImages = async (rawArgs, ctx) => {
  const limit = optionalInt(rawArgs, "limit", 1, 100, 25);
  if (limit === null) return errorResult("Invalid tool arguments");
  return ok({ ...await scanImages(limit, ctx.signal) });
};
var handleInspectImage = async (rawArgs, ctx) => {
  const selector = readStringArg(rawArgs, "selector");
  const url = readStringArg(rawArgs, "url");
  if (selector.kind === "invalid") return errorResult(selector.reason);
  if (url.kind === "invalid") return errorResult(url.reason);
  const hasSelector = selector.kind === "ok";
  const hasUrl = url.kind === "ok";
  if (!hasSelector && !hasUrl) {
    return errorResult("Provide either `selector` or `url`.");
  }
  if (hasSelector && hasUrl) {
    return errorResult("Provide only one of `selector` or `url`, not both.");
  }
  const result = await inspectImage(
    {
      ...selector.kind === "ok" ? { selector: selector.value } : {},
      ...url.kind === "ok" ? { url: url.value } : {}
    },
    ctx.signal
  );
  return ok({ ...result });
};
function wrapErrors(h) {
  return async (args, ctx) => {
    try {
      return await h(args, ctx);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  };
}
var c2paPack = {
  kind: "static",
  name: "c2pa",
  tools: TOOLS,
  handlers: {
    scan_images_c2pa: wrapErrors(handleScanImages),
    inspect_image_c2pa: wrapErrors(handleInspectImage)
  }
};

// src/bridge/packs/mcp-server-client/mcp-http-utils.ts
var MCP_TIMEOUT_MS = 2e4;
var MCP_MAX_BYTES = 8 * 1024 * 1024;
var MCP_MAX_RESPONSE_CHUNKS = 65536;
var MCP_MAX_LIST_PAGES = 20;
var MCP_MAX_TOOLS = 200;
var MCP_MAX_TOOL_NAME_CHARS = 128;
var MCP_MAX_DESCRIPTION_CHARS = 4096;
var MCP_MAX_SCHEMA_BYTES = 32 * 1024;
var MCP_MAX_TOOL_LIST_BYTES = 2 * 1024 * 1024;
var MCP_MAX_STRUCTURED_CONTENT_BYTES = 64 * 1024;
var MCP_MAX_CONTENT_TEXT_BYTES = 64 * 1024;
var MCP_MAX_CONTENT_TEXT_TOTAL_BYTES = 256 * 1024;
var RPC_ID = 1;
var MCP_CLIENT_INFO = {
  name: "cloudflare-webmcp-bridge",
  version: "0.0.1"
};
var encoder = new TextEncoder();
var DISALLOWED_FORMAT_CONTROL_CLASS = "[\\u202A-\\u202E\\u2066-\\u2069\\u200E\\u200F\\u061C\\u200B-\\u200D\\u2060\\uFEFF\\u{E0000}-\\u{E007F}]";
var DISALLOWED_FORMAT_CONTROLS_ALL_REGEX = new RegExp(
  DISALLOWED_FORMAT_CONTROL_CLASS,
  "gu"
);
var DISALLOWED_FORMAT_CONTROLS_ANY_REGEX = new RegExp(
  DISALLOWED_FORMAT_CONTROL_CLASS,
  "u"
);
function stripInvisibleControls(text) {
  return text.replace(DISALLOWED_FORMAT_CONTROLS_ALL_REGEX, "");
}
function formatToolNameForLog(name) {
  return JSON.stringify(name).replace(
    DISALLOWED_FORMAT_CONTROLS_ALL_REGEX,
    (character) => {
      const codePoint = character.codePointAt(0);
      return codePoint === void 0 ? "" : `\\u{${codePoint.toString(16).toUpperCase()}}`;
    }
  );
}
function hasInvisibleControls(text) {
  return DISALLOWED_FORMAT_CONTROLS_ANY_REGEX.test(text);
}
var McpHttpError = class extends Error {
  constructor(status, rpcError) {
    super(rpcError?.message ?? `MCP endpoint returned HTTP ${status}`);
    this.status = status;
    this.rpcError = rpcError;
  }
  status;
  rpcError;
  _tag = "McpHttpError";
};
function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function sliceUtf8Bytes(s, maxBytes) {
  const bytes = encoder.encode(s);
  if (bytes.length <= maxBytes) return s;
  let end = maxBytes;
  while (end > 0) {
    const b = bytes[end];
    if (b === void 0 || (b & 192) !== 128) break;
    end--;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.slice(0, end)
  );
}
async function readBoundedText(res) {
  const body = res.body;
  if (!body) return res.text();
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  let done = false;
  try {
    for (let count = 0; count < MCP_MAX_RESPONSE_CHUNKS; count++) {
      const { done: streamDone, value } = await reader.read();
      if (streamDone) {
        done = true;
        break;
      }
      if (value) {
        total += value.byteLength;
        if (total > MCP_MAX_BYTES) {
          throw new Error(
            `MCP response exceeded ${MCP_MAX_BYTES} bytes; aborting.`
          );
        }
        chunks.push(value);
      }
    }
    if (!done) throw new Error("MCP response exceeded chunk limit; aborting.");
  } finally {
    await reader.cancel().catch(() => {
    });
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}
function callSignal(signal) {
  const timeout = AbortSignal.timeout(MCP_TIMEOUT_MS);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}
function combineSignals(signal, lifecycleSignal) {
  return signal ? AbortSignal.any([signal, lifecycleSignal]) : lifecycleSignal;
}
async function waitFor(pending, signal) {
  if (!signal) return pending;
  if (signal.aborted) throw signal.reason;
  return new Promise((resolve2, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    pending.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve2(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      }
    );
  });
}
function assertSameOrigin(endpoint, origin) {
  if (!origin) return endpoint;
  try {
    const url = new URL(endpoint, origin);
    if (url.origin !== origin) {
      throw new Error(
        `MCP endpoint "${endpoint}" is cross-origin; only same-origin endpoints are allowed.`
      );
    }
    return url.toString();
  } catch (error) {
    if (error instanceof Error && error.message.includes("cross-origin")) {
      throw error;
    }
    throw new Error(`MCP endpoint "${endpoint}" is not a valid URL.`);
  }
}
function requestHeaders(protocolVersion, sessionId) {
  const headers = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    // Distinguish agent-mediated calls from user-initiated ones so the
    // site can attribute actions and apply different policy.
    "x-webmcp-agent": "1"
  };
  if (protocolVersion) headers["MCP-Protocol-Version"] = protocolVersion;
  if (sessionId) headers["MCP-Session-Id"] = sessionId;
  return headers;
}
async function mcpRpcResponse(endpoint, origin, method, params, options = {}) {
  const rpcId = options.rpcId ?? RPC_ID;
  const res = await fetch(assertSameOrigin(endpoint, origin), {
    method: "POST",
    headers: options.headers ?? requestHeaders(),
    credentials: "same-origin",
    redirect: "error",
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: rpcId,
      method,
      params: options.requestParams ?? params
    }),
    signal: callSignal(options.signal)
  });
  if (!res.ok) {
    let rpcError;
    const raw = await readBoundedText(res);
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        if (isObject(parsed) && isResponseEnvelope(parsed, rpcId)) {
          const error = parsed["error"];
          if (isJsonRpcError(error)) rpcError = error;
        }
      } catch {
      }
    }
    throw new McpHttpError(res.status, rpcError);
  }
  const contentType = res.headers.get("content-type") ?? "";
  const rpc = contentType.includes("text/event-stream") ? await readEventStreamResponse(res, rpcId) : parseJson(await readBoundedText(res));
  if (!isResponseEnvelope(rpc, rpcId)) {
    throw new Error("MCP endpoint returned a mismatched JSON-RPC response");
  }
  return { result: extractResult(rpc), headers: res.headers };
}
async function mcpRpcNotification(endpoint, origin, method, signal, protocolVersion, sessionId) {
  const res = await fetch(assertSameOrigin(endpoint, origin), {
    method: "POST",
    headers: requestHeaders(protocolVersion, sessionId),
    credentials: "same-origin",
    redirect: "error",
    body: JSON.stringify({ jsonrpc: "2.0", method }),
    signal: callSignal(signal)
  });
  if (!res.ok) throw new McpHttpError(res.status);
  await res.body?.cancel().catch(() => {
  });
}
async function listTools(rpc, signal) {
  const out = [];
  let totalBytes = 0;
  let cursor;
  for (let page = 0; page < MCP_MAX_LIST_PAGES; page++) {
    const result = await rpc("tools/list", cursor ? { cursor } : {}, signal);
    if (!Array.isArray(result.tools)) {
      throw new Error("MCP tools/list response has no tools array");
    }
    for (const tool of result.tools) {
      const parsed = toToolDef(tool);
      if (!parsed) continue;
      const { definition, bytes } = parsed;
      if (totalBytes + bytes > MCP_MAX_TOOL_LIST_BYTES) {
        console.warn(
          `[webmcp-interceptor] MCP tools/list exceeds ${MCP_MAX_TOOL_LIST_BYTES} bytes of tool definitions; stopping discovery early.`
        );
        return out;
      }
      totalBytes += bytes;
      out.push(definition);
      if (out.length >= MCP_MAX_TOOLS) {
        console.warn(
          `[webmcp-interceptor] MCP endpoint returned >= ${MCP_MAX_TOOLS} tools; stopping discovery early.`
        );
        return out;
      }
    }
    cursor = typeof result.nextCursor === "string" && result.nextCursor.length > 0 ? result.nextCursor : void 0;
    if (!cursor) break;
  }
  return out;
}
function toToolDef(value) {
  if (!isObject(value)) return null;
  if (typeof value.name !== "string" || value.name.trim().length === 0) return null;
  if (hasInvisibleControls(value.name)) {
    console.warn(
      `[webmcp-interceptor] mcp-server-client: skipping tool ${formatToolNameForLog(value.name)} because its name contains bidi or invisible controls.`
    );
    return null;
  }
  if (value.name.length > MCP_MAX_TOOL_NAME_CHARS) {
    console.warn(
      `[webmcp-interceptor] mcp-server-client: skipping tool ${formatToolNameForLog(value.name.slice(0, 32) + "\u2026")} because its name exceeds ${MCP_MAX_TOOL_NAME_CHARS} characters.`
    );
    return null;
  }
  const definition = { name: value.name };
  if (typeof value.description === "string" && value.description.trim().length > 0) {
    definition.description = value.description.length > MCP_MAX_DESCRIPTION_CHARS ? value.description.slice(0, MCP_MAX_DESCRIPTION_CHARS) : value.description;
  }
  if (isObject(value.inputSchema) && value.inputSchema["type"] === "object") {
    const schemaBytes = serializedBytes(value.inputSchema);
    if (schemaBytes === void 0 || schemaBytes > MCP_MAX_SCHEMA_BYTES) {
      console.warn(
        `[webmcp-interceptor] mcp-server-client: skipping tool ${formatToolNameForLog(value.name)} because its inputSchema is unserializable or exceeds ${MCP_MAX_SCHEMA_BYTES} bytes.`
      );
      return null;
    }
    definition.inputSchema = value.inputSchema;
  }
  const bytes = serializedBytes(definition);
  if (bytes === void 0) return null;
  return { definition, bytes };
}
function serializedBytes(value) {
  try {
    return encoder.encode(JSON.stringify(value)).length;
  } catch {
    return void 0;
  }
}
function toCallResult(result) {
  if (!Array.isArray(result.content)) {
    throw new Error("MCP tools/call result has no content array");
  }
  let textTotal = 0;
  const cappedContent = result.content.filter(isContentBlock).map((block) => {
    if (isObject(block) && block["type"] === "text") {
      const text = block["text"];
      if (typeof text === "string") {
        const remaining = MCP_MAX_CONTENT_TEXT_TOTAL_BYTES - textTotal;
        if (remaining <= 0) return { type: "text", text: "" };
        let capped = text;
        if (encoder.encode(capped).length > MCP_MAX_CONTENT_TEXT_BYTES) {
          capped = sliceUtf8Bytes(capped, MCP_MAX_CONTENT_TEXT_BYTES);
        }
        if (encoder.encode(capped).length > remaining) {
          capped = sliceUtf8Bytes(capped, remaining);
        }
        textTotal += encoder.encode(capped).length;
        return { type: "text", text: capped };
      }
    }
    return block;
  });
  const out = {
    content: cappedContent,
    isError: result.isError === true
  };
  if (isObject(result.structuredContent)) {
    try {
      const size = encoder.encode(JSON.stringify(result.structuredContent)).length;
      if (size <= MCP_MAX_STRUCTURED_CONTENT_BYTES) {
        out.structuredContent = result.structuredContent;
      } else {
        console.warn(
          `[webmcp-interceptor] mcp-server-client: structuredContent exceeds ${MCP_MAX_STRUCTURED_CONTENT_BYTES} bytes; dropping.`
        );
      }
    } catch {
    }
  }
  return out;
}
function isContentBlock(value) {
  if (!isObject(value) || typeof value["type"] !== "string") return false;
  if (value["type"] === "text") return typeof value["text"] === "string";
  return true;
}
function parseJson(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("MCP endpoint returned a non-JSON response");
  }
}
async function readEventStreamResponse(res, rpcId = RPC_ID) {
  const body = res.body;
  if (!body) return parseEventStream(await res.text());
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let tail = "";
  let total = 0;
  try {
    for (; ; ) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MCP_MAX_BYTES) {
        throw new Error(`MCP response exceeded ${MCP_MAX_BYTES} bytes; aborting.`);
      }
      const chunk = decoder.decode(value, { stream: true });
      let position = 0;
      let newline;
      while ((newline = chunk.indexOf("\n", position)) >= 0) {
        const rawLine = tail + chunk.slice(position, newline);
        tail = "";
        position = newline + 1;
        const envelope2 = tryParseDataLine(rawLine, rpcId);
        if (envelope2 !== void 0) return envelope2;
      }
      tail += chunk.slice(position);
    }
    const envelope = tryParseDataLine(tail, rpcId);
    if (envelope !== void 0) return envelope;
  } finally {
    await reader.cancel().catch(() => {
    });
  }
  throw new Error("MCP event stream contained no JSON-RPC response");
}
function parseEventStream(raw) {
  for (const rawLine of raw.split(/\r?\n/)) {
    const envelope = tryParseDataLine(rawLine, RPC_ID);
    if (envelope !== void 0) return envelope;
  }
  throw new Error("MCP event stream contained no JSON-RPC response");
}
function tryParseDataLine(rawLine, rpcId) {
  const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
  if (!line.startsWith("data:")) return void 0;
  const payload = line.slice("data:".length).trim();
  if (!payload) return void 0;
  try {
    const parsed = JSON.parse(payload);
    if (isResponseEnvelope(parsed, rpcId)) return parsed;
  } catch {
  }
  return void 0;
}
function isResponseEnvelope(value, rpcId) {
  if (!isObject(value) || value["jsonrpc"] !== "2.0") return false;
  const id = value["id"];
  return id === rpcId || id === null && isJsonRpcError(value["error"]);
}
function isJsonRpcError(value) {
  return isObject(value) && typeof value["code"] === "number" && Number.isInteger(value["code"]) && typeof value["message"] === "string";
}
function extractResult(rpc) {
  if (!isObject(rpc)) {
    throw new Error("Malformed JSON-RPC response from MCP endpoint");
  }
  if ("error" in rpc) {
    const error = rpc.error;
    if (!isJsonRpcError(error)) {
      throw new Error("MCP endpoint returned a malformed JSON-RPC error");
    }
    throw new Error(`MCP endpoint error: ${error["message"]}`);
  }
  const result = rpc.result;
  if (!isObject(result)) throw new Error("MCP response missing result");
  return result;
}
async function terminateMcpSession(endpoint, origin, protocolVersion, sessionId) {
  try {
    await fetch(assertSameOrigin(endpoint, origin), {
      method: "DELETE",
      headers: requestHeaders(protocolVersion, sessionId),
      credentials: "same-origin",
      redirect: "error",
      keepalive: true,
      signal: AbortSignal.timeout(MCP_TIMEOUT_MS)
    });
  } catch {
  }
}

// src/bridge/packs/mcp-server-client/initialized-client.ts
var MCP_INITIALIZE_MAX_ATTEMPTS = 2;
var MCP_MAX_SESSION_ID_LENGTH = 512;
var MCP_SUPPORTED_PROTOCOL_VERSIONS = [
  "2025-11-25",
  "2025-06-18",
  "2025-03-26"
];
var InitializedClient = class {
  constructor(options) {
    this.options = options;
  }
  options;
  protocolVersion;
  sessionId;
  initializing;
  get negotiatedProtocolVersion() {
    return this.protocolVersion;
  }
  async connect(signal) {
    await this.ensureInitialized(signal);
  }
  async listTools(signal) {
    return listTools(
      (method, params, requestSignal) => this.sessionRpc(method, params, requestSignal),
      signal
    );
  }
  async callTool(name, args, signal) {
    return toCallResult(
      await this.sessionRpc("tools/call", { name, arguments: args }, signal)
    );
  }
  async close() {
    const sessionId = this.sessionId;
    const protocolVersion = this.protocolVersion;
    this.clearSession();
    if (!sessionId || !protocolVersion) return;
    await terminateMcpSession(
      this.options.endpoint,
      this.options.origin,
      protocolVersion,
      sessionId
    );
  }
  async ensureInitialized(signal) {
    this.options.assertOpen();
    if (this.protocolVersion) return;
    this.initializing ??= this.initialize().finally(() => {
      this.initializing = void 0;
    });
    await waitFor(this.initializing, signal);
    this.options.assertOpen();
  }
  async initialize() {
    for (let attempt = 0; attempt < MCP_INITIALIZE_MAX_ATTEMPTS; attempt++) {
      this.options.assertOpen();
      const response = await mcpRpcResponse(
        this.options.endpoint,
        this.options.origin,
        "initialize",
        {
          protocolVersion: MCP_SUPPORTED_PROTOCOL_VERSIONS[0],
          capabilities: {},
          clientInfo: MCP_CLIENT_INFO
        },
        {
          signal: this.options.lifecycleSignal,
          rpcId: this.options.nextRpcId()
        }
      );
      const sessionId = readSessionId(response.headers);
      const protocolVersion = response.result["protocolVersion"];
      try {
        this.options.assertOpen();
      } catch (error) {
        if (sessionId) {
          void terminateMcpSession(
            this.options.endpoint,
            this.options.origin,
            typeof protocolVersion === "string" ? protocolVersion : MCP_SUPPORTED_PROTOCOL_VERSIONS[0],
            sessionId
          );
        }
        throw error;
      }
      try {
        if (typeof protocolVersion !== "string" || !MCP_SUPPORTED_PROTOCOL_VERSIONS.includes(protocolVersion)) {
          throw new Error(
            `MCP server negotiated unsupported protocol version: ${String(protocolVersion)}`
          );
        }
        const capabilities = response.result["capabilities"];
        if (!isObject(capabilities) || !isObject(capabilities["tools"])) {
          throw new Error("MCP server does not advertise the tools capability");
        }
      } catch (error) {
        if (sessionId) {
          void terminateMcpSession(
            this.options.endpoint,
            this.options.origin,
            typeof protocolVersion === "string" ? protocolVersion : MCP_SUPPORTED_PROTOCOL_VERSIONS[0],
            sessionId
          );
        }
        throw error;
      }
      try {
        await mcpRpcNotification(
          this.options.endpoint,
          this.options.origin,
          "notifications/initialized",
          this.options.lifecycleSignal,
          protocolVersion,
          sessionId
        );
        this.options.assertOpen();
        this.protocolVersion = protocolVersion;
        this.sessionId = sessionId;
        return;
      } catch (error) {
        const sessionMissing = error instanceof McpHttpError && error.status === 404 && sessionId !== void 0;
        if (sessionMissing && attempt + 1 < MCP_INITIALIZE_MAX_ATTEMPTS) continue;
        if (sessionId && !sessionMissing) {
          void terminateMcpSession(
            this.options.endpoint,
            this.options.origin,
            protocolVersion,
            sessionId
          );
        }
        throw error;
      }
    }
  }
  async sessionRpc(method, params, signal) {
    await this.ensureInitialized(signal);
    this.options.assertOpen();
    const sessionId = this.sessionId;
    try {
      return await this.rpcWithCurrentSession(method, params, signal);
    } catch (error) {
      if (!(error instanceof McpHttpError) || error.status !== 404 || !sessionId) {
        throw error;
      }
      this.options.assertOpen();
      if (this.sessionId === sessionId) this.clearSession();
      await this.ensureInitialized(signal);
      return this.rpcWithCurrentSession(method, params, signal);
    }
  }
  async rpcWithCurrentSession(method, params, signal) {
    const protocolVersion = this.protocolVersion;
    if (!protocolVersion) throw new Error("MCP client is not initialized");
    this.options.assertOpen();
    return (await mcpRpcResponse(
      this.options.endpoint,
      this.options.origin,
      method,
      params,
      {
        signal: combineSignals(signal, this.options.lifecycleSignal),
        headers: requestHeaders(protocolVersion, this.sessionId),
        rpcId: this.options.nextRpcId()
      }
    )).result;
  }
  clearSession() {
    this.protocolVersion = void 0;
    this.sessionId = void 0;
  }
};
function readSessionId(headers) {
  const sessionId = headers.get("MCP-Session-Id");
  if (sessionId === null) return void 0;
  if (sessionId.length === 0 || sessionId.length > MCP_MAX_SESSION_ID_LENGTH || !/^[\x21-\x7e]+$/.test(sessionId)) {
    throw new Error("MCP endpoint returned an invalid session ID");
  }
  return sessionId;
}

// src/bridge/packs/mcp-server-client/per-request-client.ts
var MCP_PER_REQUEST_PROTOCOL_VERSION = "2026-07-28";
var MCP_UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE = -32022;
var MCP_MAX_HEADER_BINDINGS = 64;
var MCP_MAX_HEADER_VALUE_BYTES = 8 * 1024;
var MCP_MAX_SCHEMA_PROPERTIES = 256;
var headerEncoder = new TextEncoder();
var InitializedFallbackRequired = class extends Error {
};
var PerRequestProtocolSelectedError = class extends Error {
  constructor(originalError) {
    super("Per-request MCP protocol was selected before a later request failed");
    this.originalError = originalError;
  }
  originalError;
};
var PerRequestClient = class {
  constructor(options) {
    this.options = options;
  }
  options;
  // Only the compiled header bindings are retained per tool, never the
  // server's description or inputSchema, so the cache stays bounded.
  headerBindings = /* @__PURE__ */ new Map();
  async discoverTools() {
    let responseReceived = false;
    try {
      const tools = await listTools(
        async (method, params, signal) => {
          return this.rpc(method, params, signal, () => {
            responseReceived = true;
          });
        },
        this.options.lifecycleSignal
      );
      return this.rememberTools(tools);
    } catch (error) {
      if (responseReceived) throw new PerRequestProtocolSelectedError(error);
      if (!responseReceived && shouldFallbackToInitializedMode(error)) {
        throw new InitializedFallbackRequired();
      }
      throw error;
    }
  }
  async listTools(signal) {
    return this.rememberTools(
      await listTools(
        (method, params, requestSignal) => this.rpc(method, params, requestSignal),
        signal
      )
    );
  }
  async callTool(name, args, signal) {
    return toCallResult(
      await this.rpc("tools/call", { name, arguments: args }, signal)
    );
  }
  async rpc(method, params, signal, onResponse) {
    this.options.assertOpen();
    const toolName = typeof params["name"] === "string" ? params["name"] : void 0;
    const response = await mcpRpcResponse(
      this.options.endpoint,
      this.options.origin,
      method,
      params,
      {
        signal: combineSignals(signal, this.options.lifecycleSignal),
        rpcId: this.options.nextRpcId(),
        headers: buildPerRequestHeaders(
          requestHeaders(MCP_PER_REQUEST_PROTOCOL_VERSION),
          method,
          params,
          toolName ? this.headerBindings.get(toolName) : void 0
        ),
        requestParams: {
          ...params,
          _meta: {
            "io.modelcontextprotocol/protocolVersion": MCP_PER_REQUEST_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": MCP_CLIENT_INFO,
            "io.modelcontextprotocol/clientCapabilities": {}
          }
        }
      }
    );
    onResponse?.();
    const resultType = response.result["resultType"];
    if (resultType !== void 0 && resultType !== "complete") {
      throw new Error(
        `MCP endpoint returned unsupported resultType: ${String(resultType)}`
      );
    }
    return response.result;
  }
  rememberTools(tools) {
    this.headerBindings.clear();
    return tools.filter((tool) => {
      const { bindings, error } = readHeaderBindings(tool.inputSchema);
      if (error) {
        console.warn(
          `[webmcp-interceptor] mcp-server-client: skipping ${tool.name}: ${error}.`
        );
        return false;
      }
      this.headerBindings.set(tool.name, bindings);
      return true;
    });
  }
};
function shouldFallbackToInitializedMode(error) {
  if (!(error instanceof McpHttpError) || error.status !== 400) return false;
  if (error.rpcError?.code !== MCP_UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE) {
    return true;
  }
  if (!isObject(error.rpcError.data)) return true;
  const supported = error.rpcError.data["supported"];
  if (!Array.isArray(supported) || supported.length === 0 || !supported.every((version) => typeof version === "string")) {
    return true;
  }
  if (supported.includes(MCP_PER_REQUEST_PROTOCOL_VERSION)) return false;
  const perRequestVersions = supported.filter(
    (version) => version >= MCP_PER_REQUEST_PROTOCOL_VERSION
  );
  if (perRequestVersions.length > 0) {
    console.warn(
      `[webmcp-interceptor] mcp-server-client: server advertised unsupported MCP protocol version(s) ${perRequestVersions.join(", ")}; this bridge supports ${MCP_PER_REQUEST_PROTOCOL_VERSION}.`
    );
    return false;
  }
  return true;
}
function encodeHeaderValue(value) {
  const bytes = headerEncoder.encode(value);
  let encoded;
  if (value.length > 0 && value === value.trim() && /^[\x20-\x7e]+$/.test(value) && !(value.startsWith("=?base64?") && value.endsWith("?="))) {
    encoded = value;
  } else {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    encoded = `=?base64?${btoa(binary)}?=`;
  }
  if (encoded.length > MCP_MAX_HEADER_VALUE_BYTES) {
    throw new Error("MCP header value exceeds size limit");
  }
  return encoded;
}
function readHeaderBindings(schema) {
  if (!schema || !isObject(schema["properties"])) return { bindings: [] };
  const bindings = [];
  const headerNames = /* @__PURE__ */ new Set();
  const properties = Object.entries(schema["properties"]);
  if (properties.length > MCP_MAX_SCHEMA_PROPERTIES) {
    return { bindings: [], error: "too many schema properties" };
  }
  for (const [argumentName, property] of properties) {
    if (!isObject(property) || property["x-mcp-header"] === void 0) continue;
    const headerName = property["x-mcp-header"];
    const type = property["type"];
    if (typeof headerName !== "string" || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(headerName) || type !== "string" && type !== "integer" && type !== "boolean") {
      return { bindings: [], error: "invalid x-mcp-header annotation" };
    }
    const normalizedName = headerName.toLowerCase();
    if (headerNames.has(normalizedName)) {
      return { bindings: [], error: "duplicate x-mcp-header annotation" };
    }
    if (bindings.length >= MCP_MAX_HEADER_BINDINGS) {
      return { bindings: [], error: "too many x-mcp-header annotations" };
    }
    headerNames.add(normalizedName);
    bindings.push({ headerName, argumentName, type });
  }
  return { bindings };
}
function buildPerRequestHeaders(baseHeaders, method, params, bindings) {
  const headers = {
    ...baseHeaders,
    "Mcp-Method": method
  };
  const toolName = params["name"];
  if (typeof toolName === "string") {
    headers["Mcp-Name"] = encodeHeaderValue(toolName);
  }
  if (!bindings || !isObject(params["arguments"])) return headers;
  for (const binding of bindings) {
    if (!Object.hasOwn(params["arguments"], binding.argumentName)) continue;
    const value = params["arguments"][binding.argumentName];
    if (value === void 0 || value === null) continue;
    const valid = binding.type === "string" && typeof value === "string" || binding.type === "boolean" && typeof value === "boolean" || binding.type === "integer" && typeof value === "number" && Number.isSafeInteger(value);
    if (!valid) {
      throw new Error(`${String(toolName)}: invalid ${binding.argumentName}`);
    }
    headers[`Mcp-Param-${binding.headerName}`] = encodeHeaderValue(String(value));
  }
  return headers;
}

// src/bridge/packs/mcp-server-client/mcp-client.ts
var McpHttpClient = class {
  selectedClient;
  negotiating;
  pagehideHandler;
  lifecycleController = new AbortController();
  perRequestClient;
  initializedClient;
  closed = false;
  rpcId = 0;
  constructor(endpoint, origin) {
    const options = {
      endpoint,
      origin,
      lifecycleSignal: this.lifecycleController.signal,
      nextRpcId: () => this.nextRpcId(),
      assertOpen: () => this.assertOpen()
    };
    this.perRequestClient = new PerRequestClient(options);
    this.initializedClient = new InitializedClient(options);
  }
  async listTools(signal) {
    const initialTools = await this.ensureClient(signal);
    if (initialTools) return initialTools;
    return this.requireSelectedClient().listTools(signal);
  }
  async callTool(name, args, signal) {
    await this.ensureClient(signal);
    return this.requireSelectedClient().callTool(name, args, signal);
  }
  attachPageLifecycle() {
    if (typeof window === "undefined" || this.pagehideHandler || this.closed) return;
    this.pagehideHandler = (event) => {
      if (event.persisted) return;
      if (this.pagehideHandler) {
        window.removeEventListener("pagehide", this.pagehideHandler);
        this.pagehideHandler = void 0;
      }
      void this.close();
    };
    window.addEventListener("pagehide", this.pagehideHandler);
  }
  async close() {
    if (this.closed) return;
    this.closed = true;
    this.lifecycleController.abort();
    if (typeof window !== "undefined" && this.pagehideHandler) {
      window.removeEventListener("pagehide", this.pagehideHandler);
      this.pagehideHandler = void 0;
    }
    await this.initializedClient.close();
  }
  async ensureClient(signal) {
    this.assertOpen();
    if (this.selectedClient) return void 0;
    this.negotiating ??= this.negotiate().finally(() => {
      this.negotiating = void 0;
    });
    const tools = await waitFor(this.negotiating, signal);
    this.assertOpen();
    return tools;
  }
  async negotiate() {
    try {
      const tools = await this.perRequestClient.discoverTools();
      this.assertOpen();
      this.selectedClient = this.perRequestClient;
      return tools;
    } catch (error) {
      if (error instanceof PerRequestProtocolSelectedError) {
        this.selectedClient = this.perRequestClient;
        throw error.originalError;
      }
      if (!(error instanceof InitializedFallbackRequired)) throw error;
      await this.initializedClient.connect();
      this.assertOpen();
      this.selectedClient = this.initializedClient;
      console.warn(
        `[webmcp-interceptor] mcp-server-client: falling back from MCP ${MCP_PER_REQUEST_PROTOCOL_VERSION} to initialized MCP ${this.initializedClient.negotiatedProtocolVersion}.`
      );
      return void 0;
    }
  }
  requireSelectedClient() {
    if (!this.selectedClient) {
      throw new Error("MCP client has not selected a protocol mode");
    }
    return this.selectedClient;
  }
  assertOpen() {
    if (this.closed) throw new Error("MCP client is closed");
  }
  nextRpcId() {
    this.rpcId += 1;
    return this.rpcId;
  }
};

// src/bridge/packs/mcp-server-client/index.ts
function isObject2(v) {
  return typeof v === "object" && v !== null;
}
var SITE_TOOL_NOTE = "[Site-provided MCP tool \u2014 executes with your session credentials.] ";
function clampDescription(desc) {
  return desc.length > MCP_MAX_DESCRIPTION_CHARS ? desc.slice(0, MCP_MAX_DESCRIPTION_CHARS) : desc;
}
function sanitiseDescription(desc, name) {
  const stripped = stripInvisibleControls(desc);
  if (stripped !== desc) {
    console.warn(
      `[webmcp-interceptor] mcp-server-client: removed bidi or invisible controls from the description of tool ${formatToolNameForLog(name)}.`
    );
  }
  return clampDescription(stripped.trim().length > 0 ? stripped : name);
}
function safeInputSchema(schema) {
  if (!isObject2(schema) || schema["type"] !== "object") {
    return { type: "object", properties: {} };
  }
  return schema;
}
function makeHandler(client, toolName) {
  return async (rawArgs, ctx) => {
    const args = isObject2(rawArgs) ? rawArgs : {};
    try {
      const result = await client.callTool(toolName, args, ctx.signal);
      const out = {
        content: result.content
      };
      if (isObject2(result.structuredContent)) {
        out.structuredContent = result.structuredContent;
      }
      if (result.isError) out.isError = true;
      return customResult(out);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  };
}
async function resolve(ctx) {
  const endpoint = ctx.mcpUrl;
  if (!endpoint) {
    return { tools: [], handlers: {} };
  }
  let defs;
  const client = new McpHttpClient(endpoint, ctx.origin);
  client.attachPageLifecycle();
  try {
    defs = await client.listTools(ctx.signal);
  } catch (err) {
    console.warn(
      `[webmcp-interceptor] mcp-server-client: tools/list failed for "${endpoint}"; registering no site tools.`,
      err
    );
    void client.close();
    return { tools: [], handlers: {} };
  }
  if (defs.length === 0) {
    void client.close();
    return { tools: [], handlers: {} };
  }
  const tools = [];
  const handlers = {};
  for (const def of defs) {
    tools.push({
      name: def.name,
      // Prepend a provenance note so the agent can distinguish site-
      // provided tools from built-ins, and cap the description length so
      // a hostile endpoint can't flood the agent via an oversized
      // description.
      description: SITE_TOOL_NOTE + sanitiseDescription(def.description || def.name, def.name),
      inputSchema: safeInputSchema(def.inputSchema)
    });
    handlers[def.name] = makeHandler(client, def.name);
  }
  console.debug(
    `[webmcp-interceptor] mcp-server-client: registered ${tools.length} site tool(s) from ${endpoint}.`
  );
  return { tools, handlers };
}
var mcpServerClientPack = {
  kind: "dynamic",
  name: "mcp-server-client",
  resolve
};

// src/bridge/bridge.ts
var ALL_PACKS = [c2paPack, mcpServerClientPack];
var DEFAULT_ACTIVE_PACKS = [];
function resolveOwnScript() {
  const candidates = Array.from(
    document.querySelectorAll("script[src]")
  );
  try {
    const selfUrl = import.meta.url;
    const exact = candidates.find((s) => s.src === selfUrl);
    if (exact) return exact;
  } catch {
  }
  return candidates.find((s) => s.src.includes("/.webmcp/bridge.js")) ?? null;
}
var script = resolveOwnScript();
initBridge().catch((err) => {
  console.error("[webmcp-interceptor] Bridge initialisation failed:", err);
});
async function initBridge() {
  const mc = resolveModelContext();
  if (!mc) {
    console.warn(
      "[webmcp-interceptor] document.modelContext is not available.\nTo enable WebMCP, use Chrome M146+ and enable:\nchrome://flags/#enable-experimental-web-platform-features"
    );
    return;
  }
  const workerBaseUrl = resolveWorkerBaseUrl();
  const mcpUrl = normalizeMcpUrl(script?.dataset["mcpUrl"]);
  const ctx = {
    origin: window.location.origin,
    workerRpc: workerBaseUrl ? makeWorkerRpc(workerBaseUrl) : workerRpcUnavailable,
    ...mcpUrl ? { mcpUrl } : {}
  };
  const activePacks = selectActivePacks(
    ALL_PACKS,
    parsePackList(script?.dataset["packs"]),
    DEFAULT_ACTIVE_PACKS
  );
  const staticResolved = resolveStaticPacks(activePacks);
  const staticRegistry = buildRegistry(staticResolved);
  registerTools(mc, ctx, staticRegistry);
  const registeredNames = new Set(staticRegistry.tools.map((t) => t.name));
  console.debug(
    `[webmcp-interceptor] Registered ${staticRegistry.tools.length} static tool(s); resolving dynamic packs\u2026`
  );
  const dynamicResolved = await resolveDynamicPacks(activePacks, ctx);
  if (dynamicResolved.length > 0) {
    const combined = buildRegistry([...staticResolved, ...dynamicResolved]);
    const additions = {
      tools: combined.tools.filter((t) => !registeredNames.has(t.name)),
      handlers: combined.handlers
    };
    registerTools(mc, ctx, additions);
    console.debug(
      `[webmcp-interceptor] Registered ${additions.tools.length} dynamic tool(s) from ${dynamicResolved.length} dynamic pack(s).`
    );
  }
}
function registerTools(mc, ctx, registry) {
  for (const tool of registry.tools) {
    const handler = registry.handlers[tool.name];
    if (!handler) continue;
    const webmcpTool = {
      name: tool.name,
      // MCP's `Tool.description` is optional but WebMCP's
      // `registerTool()` requires a non-empty string. Fall back to
      // the tool name when the description is missing OR empty (`??`
      // alone would let an empty string through) so registration never
      // fails — the agent at least sees the name.
      description: tool.description || tool.name,
      inputSchema: tool.inputSchema,
      // WebMCP may pass an options bag with an AbortSignal as the
      // second argument; forward it so handlers can cancel in-flight
      // work. When absent, the per-call context simply has no signal.
      // The spec makes `options` required, but older Chrome builds may
      // omit it, so keep the optional chain.
      execute: (args, options) => invokeHandler(tool.name, handler, args, {
        ...ctx,
        ...options?.signal ? { signal: options.signal } : {}
      })
    };
    const warn = (err) => console.warn(
      `[webmcp-interceptor] Failed to register tool "${tool.name}":`,
      err
    );
    try {
      Promise.resolve(mc.registerTool(webmcpTool)).catch(warn);
    } catch (err) {
      warn(err);
    }
  }
}
async function invokeHandler(toolName, handler, args, ctx) {
  let result;
  try {
    result = await handler(args, ctx);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(`[webmcp-interceptor] Tool "${toolName}" threw:`, message);
    throw new Error(message);
  }
  if (result.isError) {
    const text = extractText(result) ?? `${toolName} failed`;
    const error = new Error(text, { cause: result });
    error.webmcpResult = result;
    throw error;
  }
  if (result.structuredContent !== void 0) return result.structuredContent;
  return extractText(result) ?? null;
}
function extractText(r) {
  if (!r.content || r.content.length === 0) return null;
  const texts = [];
  for (const block of r.content) {
    if (block.type === "text") texts.push(block.text);
  }
  return texts.length === 0 ? null : texts.join("\n");
}
function resolveWorkerBaseUrl() {
  let src = script?.src;
  if (!src) {
    try {
      src = import.meta.url;
    } catch {
      src = void 0;
    }
  }
  if (!src) return null;
  try {
    const url = new URL(src);
    const webmcpIndex = url.pathname.indexOf("/.webmcp/");
    if (webmcpIndex >= 0) {
      url.pathname = url.pathname.slice(0, webmcpIndex);
    }
    url.search = "";
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch {
    return null;
  }
}
function makeWorkerRpc(baseUrl) {
  return async (path, body, validate) => {
    const url = `${baseUrl}/.webmcp/rpc/${path.replace(/^\//, "")}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      // Important: NOT `credentials: 'include'`. The worker is on a
      // different origin and we don't want to forward the page's
      // cookies to it. Each pack is responsible for sending whatever
      // worker-specific auth it needs (today, none).
      body: JSON.stringify(body)
    });
    const text = await res.text();
    let parsed;
    try {
      parsed = text === "" ? null : JSON.parse(text);
    } catch {
      throw new Error(`Worker returned non-JSON response (HTTP ${res.status})`);
    }
    if (!res.ok) {
      const message = parsed && typeof parsed === "object" && "error" in parsed && typeof parsed.error === "string" ? parsed.error : `Worker RPC failed (HTTP ${res.status})`;
      throw new Error(message);
    }
    return validate(parsed);
  };
}
function workerRpcUnavailable() {
  throw new Error(
    "Worker base URL could not be determined. Worker-backed tools are unavailable on this page."
  );
}
function resolveModelContext() {
  if (document.modelContext) return document.modelContext;
  const fromNavigator = navigator.modelContext;
  return fromNavigator ?? null;
}
