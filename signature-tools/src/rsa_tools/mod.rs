use std::io::Write;

use anyhow::bail;

use num_bigint_dig::RandBigInt;
use rsa::BigUint;
pub use rsa::RsaPrivateKey;
pub use rsa::RsaPublicKey;

pub use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sha2::Digest;
use sha2::Sha256;

use crate::check_size_and_write;
use crate::sha256_for_integer;

pub mod merkle_tree;

#[derive(Debug)]
pub struct RSASignaturePubKeyEnt {
    pub r: BigUint,
    pub e: BigUint,
    pub n: BigUint,
}
#[derive(Debug)]
pub struct RSASignature {
    pub c: BigUint,
    pub i: BigUint,
    pub r_and_pubkey: Vec<RSASignaturePubKeyEnt>,
}
impl RSASignature {
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut out_buf = vec![];
        let n = self.r_and_pubkey.len();
        out_buf.write_all(&n.to_le_bytes())?;
        let mut check_size_and_write = |a: &BigUint, b: usize| -> anyhow::Result<()> {
            check_size_and_write(&mut out_buf, a, b)
        };
        check_size_and_write(&self.c, 256)?;
        check_size_and_write(&self.i, 256)?;
        for i in 0..n {
            check_size_and_write(&self.r_and_pubkey[i].r, 256)?;
            check_size_and_write(&self.r_and_pubkey[i].e, 4)?;
            check_size_and_write(&self.r_and_pubkey[i].n, 256)?;
        }
        Ok(out_buf)
    }
}


pub fn create_signature(
    all_keys: &[RsaPublicKey],
    signer_private_key: &RsaPrivateKey,
    signer: usize,
    message: &[u8],
) -> anyhow::Result<RSASignature> {
    let one = 1u32.into();
    let mut rng = rand::thread_rng();
    let skey = signer_private_key;
    let [p, q] = &skey.primes()[..2] else {
        bail!("Unexpected prime count");
    };
    let n = all_keys.len();
    let mut r_arr = vec![BigUint::default(); n];
    let mut c_arr = vec![BigUint::default(); n];
    let a = rng.gen_biguint_range(&one, skey.n());
    let h_val = sha256_for_integer(skey.n());
    let image = h_val.modpow(skey.d(), skey.n()) * p.clone() % skey.n();
    let mut hasher = Sha256::new();
    hasher.update(message);
    for key in all_keys {
        let n = key.n().to_bytes_le();
        assert_eq!(n.len(), 2048 / 8);
        hasher.update(n);
        let mut e = key.e().to_bytes_le();
        e.resize(4, 0);
        hasher.update(e);
    }

    let hash = |a: &BigUint, b: &BigUint| -> BigUint {
        let mut local_hasher = hasher.clone();
        let mut a_bytes = a.to_bytes_le();
        a_bytes.resize(256, 0);
        local_hasher.update(&a_bytes);
        let mut b_bytes = b.to_bytes_le();
        b_bytes.resize(256, 0);
        local_hasher.update(&b_bytes);
        BigUint::from_bytes_le(&local_hasher.finalize())
    };
    let qpei = q.modpow(skey.e(), skey.n());
    let sec1 = &a * &qpei % skey.n();
    let sec2 = (&a * &qpei % skey.n()) * &h_val % skey.n();
    c_arr[(signer + 1) % n] = hash(&sec1, &sec2);

    let mut i = (signer + 1) % n;
    while i != signer {
        r_arr[i] = rng.gen_biguint_range(&one, all_keys[i].n());
        let crpe = c_arr[i].clone() * r_arr[i].clone().modpow(all_keys[i].e(), all_keys[i].n())
            % all_keys[i].n();
        let ch_pi_mul_r = (c_arr[i].clone() * sha256_for_integer(all_keys[i].n()) + image.clone())
            * r_arr[i].modpow(all_keys[i].e(), all_keys[i].n())
            % all_keys[i].n();
        c_arr[(i + 1) % n] = hash(&crpe, &ch_pi_mul_r);
        i = (i + 1) % n;
    }
    let phi = (p - one.clone()) * (q - one.clone());
    r_arr[signer] = (a * c_arr[signer].modpow(&(phi - one), skey.n())).modpow(skey.d(), skey.n())
        * q.clone()
        % skey.n();
    Ok(RSASignature {
        c: c_arr[0].clone(),
        i: image,
        r_and_pubkey: r_arr
            .iter()
            .zip(all_keys)
            .map(|(a, b)| RSASignaturePubKeyEnt {
                r: a.clone(),
                e: b.e().clone(),
                n: b.n().clone(),
            })
            .collect::<Vec<_>>(),
    })
}
pub fn encode_public_key_cell(keys: &[RsaPrivateKey]) -> Vec<u8> {
    let mut buf = Vec::<u8>::new();
    buf.write_all(&(keys.len() as u16).to_le_bytes()).unwrap();
    for item in keys {
        let num_buf = item.n().to_bytes_le();
        assert_eq!(num_buf.len(), 256);
        buf.write_all(&num_buf).unwrap();
    }
    for item in keys {
        let mut num_buf = item.e().to_bytes_le();
        num_buf.resize(4, 0);
        buf.write_all(&num_buf).unwrap();
    }
    buf
}

pub struct PublicKeyIndexEntry {
    pub hash: Vec<u8>,
    pub index: u32,
}
pub fn encode_public_key_index_cell(entries: &[PublicKeyIndexEntry]) -> Vec<u8> {
    let mut buf = Vec::<u8>::new();
    buf.write_all(&(entries.len() as u16).to_le_bytes())
        .unwrap();
    for key_hash in entries.iter() {
        buf.write_all(&key_hash.hash).unwrap();
    }
    for key_hash in entries.iter() {
        buf.write_all(&key_hash.index.to_le_bytes()).unwrap();
    }
    buf
}
