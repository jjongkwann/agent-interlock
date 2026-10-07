// Deployment statements contain only strings/null. Sort Unicode code points like Python.
export function canonicalStatement(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value.replace(/\r\n?/g, '\n').normalize('NFC'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid approval statement');
  const compare = (a, b) => {
    const aa = Array.from(a, c => c.codePointAt(0)), bb = Array.from(b, c => c.codePointAt(0));
    for (let i = 0; i < Math.min(aa.length, bb.length); i++) if (aa[i] !== bb[i]) return aa[i] - bb[i];
    return aa.length - bb.length;
  };
  const normalized = {};
  for (const [key, item] of Object.entries(value)) {const k = key.replace(/\r\n?/g, '\n').normalize('NFC'); if (Object.hasOwn(normalized, k)) throw new Error('Duplicate normalized key'); normalized[k] = item;}
  value = normalized;
  return `{${Object.keys(value).sort(compare).map(k => `${JSON.stringify(k)}:${canonicalStatement(value[k])}`).join(',')}}`;
}
export async function signApproval(bytes, statement, approver) {
  let seed = bytes;
  if (bytes.length !== 32) {
    const hex = new TextDecoder().decode(bytes).trim();
    if (!/^[a-f0-9]{64}$/i.test(hex)) throw new Error('Choose a raw 32-byte seed or a file containing 64 hexadecimal characters');
    seed = Uint8Array.from(hex.match(/../g), h => parseInt(h, 16));
  }
  const pkcs8 = new Uint8Array(48);
  pkcs8.set([48,46,2,1,0,48,5,6,3,43,101,112,4,34,4,32]); pkcs8.set(seed, 16);
  let key;
  try { key = await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', false, ['sign']); }
  finally { pkcs8.fill(0); seed.fill(0); bytes.fill(0); }
  const payload = new TextEncoder().encode(canonicalStatement({...statement, approverId: approver.approverId, keyId: approver.keyId}));
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', key, payload));
  if (!/^[a-f0-9]{64}$/i.test(approver.publicKeyHex)) throw new Error('Invalid trusted public key');
  const publicKey = await crypto.subtle.importKey('raw', Uint8Array.from(approver.publicKeyHex.match(/../g), h => parseInt(h,16)), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', publicKey, signature, payload)) throw new Error('This key does not match the selected trusted approver');
  return {approverId: approver.approverId, keyId: approver.keyId, signature: `ed25519:${Array.from(signature, b => b.toString(16).padStart(2,'0')).join('')}`};
}
