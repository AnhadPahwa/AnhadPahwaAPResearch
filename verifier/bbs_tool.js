const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const bbs = require("@mattrglobal/node-bbs-signatures");

// ---------- paths ----------
const ISSUER_DIR = path.join(process.cwd(), "issuer_data");
const SK_PATH = path.join(ISSUER_DIR, "bbs_sk.json");
const PK_PATH = path.join(ISSUER_DIR, "bbs_pk.json");

// ---------- utils ----------
function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf-8"));
}
function writeJson(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
}
function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}
function unb64url(s) {
  return Buffer.from(s, "base64url");
}
function nonceBytesFromContext(contextStr) {
  // Bind proof to challenge (nonce or domain|nonce)
  return crypto.createHash("sha256").update(Buffer.from(contextStr, "utf-8")).digest();
}

// ---------- schema ----------
// Indices:
// 0 subject_pubkey
// 1 age_group
// 2 assurance_level
// 3 jurisdiction
// 4 expiry
// 5 revocation_handle
function toMessagesArray(cred) {
  return [
    cred.subject_pubkey,
    cred.claims?.age_group,
    cred.claims?.assurance_level,
    cred.claims?.jurisdiction,
    cred.expiry,
    cred.revocation_handle,
  ].map((x) => Buffer.from(String(x ?? ""), "utf-8"));
}

function parseRevealCsv(csvStr) {
  const revealed = csvStr
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => parseInt(s, 10));

  if (revealed.some((x) => Number.isNaN(x))) {
    throw new Error("Invalid revealIdxCsv: must be comma-separated integers");
  }
  return Array.from(new Set(revealed)).sort((a, b) => a - b);
}

function loadBbsKeyPair() {
  if (!fs.existsSync(SK_PATH) || !fs.existsSync(PK_PATH)) {
    throw new Error("Missing issuer_data/bbs_sk.json or issuer_data/bbs_pk.json. Run keygen first.");
  }
  const sk = readJson(SK_PATH);
  const pk = readJson(PK_PATH);

  const publicKey = Uint8Array.from(unb64url(pk.publicKey));
  const secretKey = Uint8Array.from(unb64url(sk.secretKey));

  return { publicKey, secretKey };
}

// ---------- commands ----------
async function keygenCmd() {
  const kp = await bbs.generateBls12381G2KeyPair();

  // kp: { publicKey: Uint8Array, secretKey: Uint8Array }
  if (!kp.publicKey || !kp.secretKey) {
    throw new Error("Keygen did not return { publicKey, secretKey }");
  }

  writeJson(SK_PATH, { secretKey: b64url(Buffer.from(kp.secretKey)) });
  writeJson(PK_PATH, { publicKey: b64url(Buffer.from(kp.publicKey)) });

  console.log("OK");
}

async function signCmd(credPath) {
  const keyPair = loadBbsKeyPair();
  const cred = readJson(credPath);
  const messages = toMessagesArray(cred);

  if (!Array.isArray(messages) || !messages.every(Buffer.isBuffer)) {
    throw new Error("messages must be Buffer[]");
  }

  const signature = await bbs.blsSign({
    keyPair,
    messages: messages.map((b) => Uint8Array.from(b)),
  });

  const out = {
    version: "v2",
    issuer_bbs_pubkey: { publicKey: b64url(Buffer.from(keyPair.publicKey)) },
    credential: cred,
    bbs_signature: b64url(Buffer.from(signature)),
  };

  process.stdout.write(JSON.stringify(out));
}

async function proveCmd(bundlePath, revealIdxCsv, contextStr) {
  const bundle = readJson(bundlePath);

  const pubKey = Uint8Array.from(unb64url(bundle.issuer_bbs_pubkey?.publicKey || ""));
  const cred = bundle.credential;
  const messages = toMessagesArray(cred).map((b) => Uint8Array.from(b));
  const signature = Uint8Array.from(unb64url(bundle.bbs_signature || ""));

  const revealed = parseRevealCsv(revealIdxCsv);
  const nonce = Uint8Array.from(nonceBytesFromContext(contextStr));

  if (!Array.isArray(messages) || messages.length === 0) throw new Error("messages missing");
  for (const i of revealed) {
    if (i < 0 || i >= messages.length) throw new Error(`revealed index out of range: ${i}`);
  }

  const proof = await bbs.blsCreateProof({
    publicKey: pubKey,
    messages,
    signature,
    revealed,
    nonce,
  });

  const revealedMessagesByIndex = {};
  for (const i of revealed) {
    // store revealed messages as UTF-8 strings
    revealedMessagesByIndex[i] = Buffer.from(messages[i]).toString("utf-8");
  }

  const out = {
    version: "v2",
    issuer_bbs_pubkey: bundle.issuer_bbs_pubkey,
    revealed_indices: revealed,
    revealed_messages_by_index: revealedMessagesByIndex,
    bbs_proof: b64url(Buffer.from(proof)),

    // reveal handle separately
    revocation_handle: cred.revocation_handle,
  };

  process.stdout.write(JSON.stringify(out));
}

async function verifyCmd(proofPath, contextStr) {
  const obj = readJson(proofPath);

  const pubKey = Uint8Array.from(unb64url(obj.issuer_bbs_pubkey?.publicKey || ""));
  const proof = Uint8Array.from(unb64url(obj.bbs_proof || ""));
  const revealed = obj.revealed_indices || [];
  const nonce = Uint8Array.from(nonceBytesFromContext(contextStr));

  const revealedMessages = revealed.map((i) => {
    const v = obj.revealed_messages_by_index?.[i];
    return Uint8Array.from(Buffer.from(String(v ?? ""), "utf-8"));
  });

  const ok = await bbs.blsVerifyProof({
    publicKey: pubKey,
    proof,
    revealed,
    messages: revealedMessages,
    nonce,
  });

  process.stdout.write(JSON.stringify({ ok }));
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);

  if (cmd === "keygen") return keygenCmd();
  if (cmd === "sign") return signCmd(args[0]);
  if (cmd === "prove") return proveCmd(args[0], args[1], args[2]);
  if (cmd === "verify") return verifyCmd(args[0], args[1]);

  console.error("Usage:");
  console.error("  node verifier/bbs_tool.js keygen");
  console.error("  node verifier/bbs_tool.js sign <cred.json>");
  console.error("  node verifier/bbs_tool.js prove <bundle.json> <revealIdxCsv> <contextStr>");
  console.error("  node verifier/bbs_tool.js verify <proof.json> <contextStr>");
  process.exit(1);
}

main().catch((e) => {
  console.error("ERROR:", e);
  process.exit(1);
});
