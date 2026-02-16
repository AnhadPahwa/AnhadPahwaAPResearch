const ISSUER_STATUS_URL = "http://127.0.0.1:5001/statuslist";

let revokedHandles = new Set();

async function refreshRevocation() {
  try {
    const res = await fetch(ISSUER_STATUS_URL);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const data = await res.json();
    revokedHandles = new Set(data.revoked_handles || []);
  } catch (e) {
    console.error("Revocation refresh failed:", e.message);
  }
}

// refresh every 10 seconds
setInterval(refreshRevocation, 10_000);
refreshRevocation();

function isRevoked(handle) {
  return revokedHandles.has(handle);
}

module.exports = { isRevoked };
