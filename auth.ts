import elliptic from 'elliptic';
import crypto from 'crypto';
import axlsign from 'axlsign';

const hexString2ArrayBuffer = (hexString: string): Uint8Array =>
  new Uint8Array(hexString.match(/[\da-f]{2}/gi)!.map(h => parseInt(h, 16)));

const buf2hex = (buffer: ArrayBuffer | Uint8Array | Buffer): string =>
  Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');

export {
  hexString2ArrayBuffer,
  buf2hex
};

// Note: All functions expect parameters to be hex strings.

export function pair_setup_aes_key(K: string): string {
  return crypto.createHash('sha512')
    .update('Pair-Setup-AES-Key')
    .update(hexString2ArrayBuffer(K))
    .digest('hex')
    .substring(0, 32);
}

export function pair_setup_aes_iv(K: string): string {
  let ab = crypto.createHash('sha512')
    .update('Pair-Setup-AES-IV')
    .update(hexString2ArrayBuffer(K))
    .digest();

  ab = ab.slice(0, 16);
  ab[ab.length - 1] += 0x01;

  return buf2hex(ab);
}

export function pair_verify_aes_key(shared: string): string {
  return buf2hex(
    crypto.createHash('sha512')
      .update('Pair-Verify-AES-Key')
      .update(hexString2ArrayBuffer(shared))
      .digest()
      .slice(0, 16)
  );
}

export function pair_verify_aes_iv(shared: string): string {
  return buf2hex(
    crypto.createHash('sha512')
      .update('Pair-Verify-AES-IV')
      .update(hexString2ArrayBuffer(shared))
      .digest()
      .slice(0, 16)
  );
}

// Public.

export function a_pub(a: string): string {
  return elliptic.utils.toHex(new elliptic.eddsa('ed25519').keyFromSecret(a).getPublic());
}

export function confirm(a: string, K: string): { epk: string, authTag: string } {
  const key = pair_setup_aes_key(K);
  const iv = pair_setup_aes_iv(K);

  const cipher = crypto.createCipheriv(
    'aes-128-gcm',
    hexString2ArrayBuffer(key),
    hexString2ArrayBuffer(iv)
  );

  let encrypted = cipher.update(hexString2ArrayBuffer(a_pub(a)), undefined, 'hex');
  encrypted += cipher.final('hex');

  return {
    epk: encrypted,
    authTag: buf2hex(cipher.getAuthTag())
  };
}

export function verifier(a: string): { verifierBody: Buffer, v_pri: string, v_pub: string } {
  const keyPair = axlsign.generateKeyPair(crypto.randomBytes(32));
  const v_pri = buf2hex(keyPair.private);
  const v_pub = buf2hex(keyPair.public);

  const header = Buffer.from([0x01, 0x00, 0x00, 0x00]);
  const a_pub_buf = Buffer.from(a_pub(a), 'hex');

  return {
    verifierBody: Buffer.concat(
      [header, keyPair.public, a_pub_buf],
      header.byteLength + keyPair.public.byteLength + a_pub_buf.byteLength
    ),
    v_pri,
    v_pub
  };
}

export function shared(v_pri: string, atv_pub: string): string {
  return buf2hex(
    axlsign.sharedKey(
      hexString2ArrayBuffer(v_pri),
      hexString2ArrayBuffer(atv_pub)
    )
  );
}

export function signed(a: string, v_pub: string, atv_pub: string): string {
  const key = new elliptic.eddsa('ed25519').keyFromSecret(a);

  return key.sign(v_pub + atv_pub).toHex();
}

export function signature(shared: string, atv_data: string, signed: string): string {
  const cipher = crypto.createCipheriv(
    'aes-128-ctr',
    hexString2ArrayBuffer(pair_verify_aes_key(shared)),
    hexString2ArrayBuffer(pair_verify_aes_iv(shared))
  );

  // discard the result of encrypting atv_data.
  cipher.update(hexString2ArrayBuffer(atv_data));

  let encrypted = cipher.update(Buffer.from(signed, 'hex'), undefined, 'hex');
  encrypted += cipher.final('hex');

  return encrypted;
}