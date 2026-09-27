//! THET v21 - cryptographic core

use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;
use blake2::{Blake2b512, Blake2bMac512, digest::KeyInit};
use scrypt::{scrypt, Params as ScryptParams};
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 16;
pub const MAC_LEN: usize = 64;
pub const BLOCK: usize = 32;

pub const LBL_ENC1: &[u8] = b"thet:v21:enc1";
pub const LBL_ENC2: &[u8] = b"thet:v21:enc2";
pub const LBL_ENC3: &[u8] = b"thet:v21:enc3";
pub const LBL_MAC1: &[u8] = b"thet:v21:mac1";
pub const LBL_MAC2: &[u8] = b"thet:v21:mac2";
pub const LBL_NON:  &[u8] = b"thet:v21:nonce";
pub const LBL_HKDF: &[u8] = b"thet:v21:hkdf:";

const SCRYPT_LOG_N: u8 = 17;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

pub fn encode_ad(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}

pub fn derive_master(password: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, KEY_LEN)
        .map_err(|e| format!("scrypt params: {e}"))?;
    let mut out = [0u8; KEY_LEN];
    scrypt(password, salt, &params, &mut out)
        .map_err(|e| format!("scrypt: {e}"))?;
    Ok(out)
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
    let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
    let mut out = [0u8; 64];
    out.copy_from_slice(&prk);
    out
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha512>::from_prk(prk).expect("prk too short");
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}

pub struct Keys {
    pub nonce_key: [u8; KEY_LEN],
    pub enc1: [u8; KEY_LEN],
    pub enc2: [u8; KEY_LEN],
    pub enc3: [u8; KEY_LEN],
    pub mac1: [u8; KEY_LEN],
    pub mac2: [u8; KEY_LEN],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.nonce_key.zeroize();
        self.enc1.zeroize();
        self.enc2.zeroize();
        self.enc3.zeroize();
        self.mac1.zeroize();
        self.mac2.zeroize();
    }
}

pub fn derive_keys(master: &[u8; KEY_LEN], salt: &[u8]) -> Keys {
    let prk = hkdf_extract(salt, master);
    let mut nonce_key = [0u8; KEY_LEN];
    let mut enc1 = [0u8; KEY_LEN];
    let mut enc2 = [0u8; KEY_LEN];
    let mut enc3 = [0u8; KEY_LEN];
    let mut mac1 = [0u8; KEY_LEN];
    let mut mac2 = [0u8; KEY_LEN];

    nonce_key.copy_from_slice(&hkdf_expand(&prk, &[LBL_HKDF, b"nonce"].concat(), KEY_LEN));
    enc1.copy_from_slice(&hkdf_expand(&prk, &[LBL_HKDF, b"enc1"].concat(), KEY_LEN));
    enc2.copy_from_slice(&hkdf_expand(&prk, &[LBL_HKDF, b"enc2"].concat(), KEY_LEN));
    enc3.copy_from_slice(&hkdf_expand(&prk, &[LBL_HKDF, b"enc3"].concat(), KEY_LEN));
    mac1.copy_from_slice(&hkdf_expand(&prk, &[LBL_HKDF, b"mac1"].concat(), KEY_LEN));
    mac2.copy_from_slice(&hkdf_expand(&prk, &[LBL_HKDF, b"mac2"].concat(), KEY_LEN));

    Keys { nonce_key, enc1, enc2, enc3, mac1, mac2 }
}

pub fn derive_stream_nonces(
    nonce_key: &[u8; KEY_LEN],
    base_nonce: &[u8],
) -> ([u8; NONCE_LEN], [u8; NONCE_LEN], [u8; NONCE_LEN]) {
    let mut n1 = [0u8; NONCE_LEN];
    let mut n2 = [0u8; NONCE_LEN];
    let mut n3 = [0u8; NONCE_LEN];

    let d1 = hmac_sha512(nonce_key, &[LBL_NON, b"n1:", base_nonce].concat());
    let d2 = hmac_sha512(nonce_key, &[LBL_NON, b"n2:", base_nonce].concat());
    let d3 = hmac_sha512(nonce_key, &[LBL_NON, b"n3:", base_nonce].concat());

    n1.copy_from_slice(&d1[..NONCE_LEN]);
    n2.copy_from_slice(&d2[..NONCE_LEN]);
    n3.copy_from_slice(&d3[..NONCE_LEN]);
    (n1, n2, n3)
}

pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 64];
    r.copy_from_slice(&out);
    r
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub fn hmac_sha3_256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha3_256> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub fn blake2b_32(msg: &[u8]) -> [u8; 32] {
    let mut h = Blake2b512::new();
    Digest::update(&mut h, msg);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out[..32]);
    r
}

pub fn keystream_at(
    keys: &Keys,
    n1: &[u8; NONCE_LEN],
    n2: &[u8; NONCE_LEN],
    n3: &[u8; NONCE_LEN],
    byte_offset: u64,
    nbytes: usize,
) -> Vec<u8> {
    let start_block = byte_offset / BLOCK as u64;
    let skip = (byte_offset % BLOCK as u64) as usize;
    let mut out = Vec::with_capacity(nbytes + BLOCK);
    let mut block = start_block;
    let need = nbytes + skip;
    while out.len() < need {
        let c = block.to_be_bytes();
        let s1 = hmac_sha256(&keys.enc1, &[LBL_ENC1, n1, &c].concat());
        let s2 = hmac_sha3_256(&keys.enc2, &[LBL_ENC2, n2, &c].concat());
        let s3 = blake2b_32(&[LBL_ENC3, n3, &c].concat());
        let mut ks = [0u8; 32];
        for i in 0..32 { ks[i] = s1[i] ^ s2[i] ^ s3[i]; }
        out.extend_from_slice(&ks);
        block += 1;
    }
    out[skip..skip + nbytes].to_vec()
}

pub struct DualMac {
    mac1: Hmac<Sha512>,
    mac2: Blake2bMac512,
}

impl DualMac {
    pub fn new(keys: &Keys, ad: &[u8]) -> Self {
        let mut mac1 = <Hmac<Sha512> as Mac>::new_from_slice(&keys.mac1).expect("mac1");
        mac1.update(ad);
        let mut mac2 = <Blake2bMac512 as KeyInit>::new_from_slice(&keys.mac2).expect("mac2");
        mac2.update(ad);
        Self { mac1, mac2 }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.mac1.update(data);
        self.mac2.update(data);
    }

    pub fn finalize(self) -> ([u8; MAC_LEN], [u8; MAC_LEN]) {
        let m1 = self.mac1.finalize().into_bytes();
        let mut r1 = [0u8; MAC_LEN];
        r1.copy_from_slice(&m1);
        let m2 = self.mac2.finalize().into_bytes();
        let mut r2 = [0u8; MAC_LEN];
        r2.copy_from_slice(&m2);
        (r1, r2)
    }
}
