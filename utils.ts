import sodium from "libsodium-wrappers";
import crypto from "crypto";

let ecdhOurs: Uint8Array;
let ecdhTheirs: Uint8Array;
let edTheirs: Uint8Array;
let ecdhSecret: Uint8Array;
let pairVerified = false;
let edDSAPublicKey: Uint8Array;

// Initialize the cipher with a shared secret
function initCipher() {
  // Create separate hash objects for AES key and IV
  const sha512DigestKey = crypto.createHash('sha512');
  sha512DigestKey.update("Pair-Verify-AES-Key");
  sha512DigestKey.update(ecdhSecret);
  const aesKey = sha512DigestKey.digest().slice(0, 16);

  const sha512DigestIV = crypto.createHash('sha512');
  sha512DigestIV.update("Pair-Verify-AES-IV");
  sha512DigestIV.update(ecdhSecret);
  const aesIV = sha512DigestIV.digest().slice(0, 16);

  return crypto.createCipheriv('aes-128-ctr', aesKey, aesIV);
}

export async function pairVerify(request: Buffer): Promise<Buffer> {
  await sodium.ready;

  const flag = request.readUInt8(0);
  request = request.slice(4); // Skip 3 unused bytes

  if (flag > 0) {
    // Read incoming keys
    ecdhTheirs = request.slice(0, 32);
    edTheirs = request.slice(32, 64);

    // Generate Curve25519 key pair
    const curve25519KeyPair = sodium.crypto_kx_keypair();
    ecdhOurs = curve25519KeyPair.publicKey;
    ecdhSecret = sodium.crypto_scalarmult(curve25519KeyPair.privateKey, ecdhTheirs);

    console.info("Shared secret:", Buffer.from(ecdhSecret).toString("hex"));

    // Prepare the cipher
    const aesCtr128Encrypt = initCipher();

    // Prepare data to sign
    const dataToSign = new Uint8Array(64);
    dataToSign.set(ecdhOurs, 0);
    dataToSign.set(ecdhTheirs, 32);

    // Generate Ed25519 signing key pair
    const signingKeyPair = sodium.crypto_sign_keypair();

    // Sign the data
    const signature = sodium.crypto_sign_detached(dataToSign, signingKeyPair.privateKey);

    // Encrypt the signature
    const encryptedSignature = aesCtr128Encrypt.update(signature);

    return Buffer.from(curve25519KeyPair.publicKey.buffer)

    // Construct and return the response
    const responseContent = Buffer.concat([Buffer.from(ecdhOurs), Buffer.from(encryptedSignature)]);
    return responseContent;
  } else {
    // Read and decrypt the signature
    const signature = request.slice(0, 64);

    const aesCtr128Encrypt = initCipher();

    let sigBuffer = Buffer.alloc(64);
    aesCtr128Encrypt.update(sigBuffer); // Cipher initialization step
    sigBuffer = Buffer.concat([sigBuffer, aesCtr128Encrypt.update(signature)]);

    // Prepare data to verify
    const sigMessage = new Uint8Array(64);
    sigMessage.set(ecdhTheirs, 0);
    sigMessage.set(ecdhOurs, 32);

    // Verify the signature
    edDSAPublicKey = sodium.crypto_sign_ed25519_pk_to_curve25519(edTheirs);
    pairVerified = sodium.crypto_sign_verify_detached(sigBuffer, sigMessage, edDSAPublicKey);

    console.info("Pair verified:", pairVerified);

    // Return empty buffer if this is phase 2
    return Buffer.alloc(0); // Response not required in the second phase
  }
}

// Expose helper functions
export function isPairVerified(): boolean {
  return pairVerified;
}

export function getSharedSecret(): Uint8Array {
  return ecdhSecret;
}

export function getCurve25519PublicKey(): Uint8Array {
  return ecdhOurs;
}

export function geteEd25519PublicKey(): Uint8Array {
  return edDSAPublicKey;
}

