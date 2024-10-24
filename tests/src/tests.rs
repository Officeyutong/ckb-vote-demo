use std::io::Write;

use crate::Loader;
use ckb_testtool::{bytes::BufMut, ckb_types::packed::OutPoint, context::Context};
use jose_jwk::Rsa;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rsa::traits::PrivateKeyParts;
use rsa::{traits::PublicKeyParts, BigUint, RsaPrivateKey};
use sha2::Digest;
use sha2::Sha256;

fn sha256_for_integer(num: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(num.to_bytes_le());
    BigUint::from_bytes_le(&hasher.finalize())
}

const KEY_COUNT: usize = 10000;
const CHUNK_SIZE: usize = 600;
const CANDIDATE_COUNT: usize = 100;
struct Candidate {
    id: [u8; 4],
    description: String,
}

struct PreparedState {
    public_key_index_cell: OutPoint,
    public_key_cells: Vec<OutPoint>,
    candidate_cell: OutPoint,
    keys: Vec<RsaPrivateKey>,
    candidates: Vec<Candidate>,
}

fn prepare(ctx: &mut Context) -> PreparedState {
    let keys = (0..KEY_COUNT)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            priv_key
        })
        .collect::<Vec<_>>();
    let key_cells = keys
        .chunks(CHUNK_SIZE)
        .map(|chunk| {
            let mut buf = Vec::<u8>::new();
            buf.put_u16_le(chunk.len() as _);
            for item in chunk {
                let num_buf = item.n().to_bytes_le();
                assert_eq!(num_buf.len(), 2048);
                buf.write_all(&num_buf).unwrap();
            }
            for item in chunk {
                let num_buf = item.e().to_bytes_le();
                assert_eq!(num_buf.len(), 2048);
                buf.write_all(&num_buf).unwrap();
            }
            ctx.deploy_cell(buf.into())
        })
        .collect::<Vec<_>>();
    let key_index_cell = {
        let mut buf = Vec::<u8>::new();
        buf.put_u16_le(key_cells.len() as _);
        for key_hash in key_cells.iter() {
            buf.write_all(&key_hash.tx_hash().raw_data()).unwrap();
        }
        for key_hash in key_cells.iter() {
            buf.write_all(&key_hash.index().raw_data()).unwrap();
        }
        ctx.deploy_cell(buf.into())
    };
    let mut rng = rand::thread_rng();
    let candidates = (0..CANDIDATE_COUNT)
        .map(|idx| Candidate {
            description: format!("{}-th candidate", idx),
            id: rng.gen(),
        })
        .collect::<Vec<_>>();
    let candidate_cell = {
        let mut buf = Vec::<u8>::new();
        buf.put_u16_le(candidates.len() as _);
        for item in candidates.iter() {
            buf.write_all(&item.id).unwrap();
            let mut str_bytes = item.description.as_bytes().to_vec();
            while str_bytes.len() > 99 {
                str_bytes.pop();
            }
            while str_bytes.len() < 100 {
                str_bytes.push(0);
            }
            buf.write_all(&str_bytes).unwrap()
        }
        ctx.deploy_cell(buf.into())
    };
    PreparedState {
        candidate_cell,
        candidates,
        keys,
        public_key_cells: key_cells,
        public_key_index_cell: key_index_cell,
    }
}
use num_bigint_dig::RandBigInt;

fn create_signature(all_keys: &[RsaPrivateKey], signer: usize, message: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let skey = &all_keys[signer];
    let n = all_keys.len();
    let mut r_arr = vec![BigUint::default(); n];
    let mut c_arr = vec![BigUint::default(); n];
    let a = rng.gen_biguint_range(&1u32.into(), skey.n());
    let h_val = sha256_for_integer(skey.n());
    let image = h_val.modpow(skey.d(), skey.n()) * skey.primes()[0].clone() % skey.n();
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
        local_hasher.update(a.to_bytes_le());
        local_hasher.update(b.to_bytes_le());
        BigUint::from_bytes_le(&local_hasher.finalize())
    };
    let qpei = skey.primes()[1].modpow(skey.e(), skey.n());
    c_arr[(signer + 1) % n] = hash(&(&a * &qpei % skey.n()), &(&a * &qpei * &h_val % skey.n()));
    let mut i = (signer + 1) % n;
    while i != signer {
        r_arr[i] = rng.gen_biguint_range(&(1u32).into(), all_keys[i].n());
        let crpe = c_arr[i].clone() * r_arr[i].clone().modpow(all_keys[i].e(), all_keys[i].n())
            % all_keys[i].n();
        let ch_pi_mul_r = (c_arr[i].clone() * sha256_for_integer(all_keys[i].n()) + image.clone())
            * r_arr[i].modpow(all_keys[i].e(), all_keys[i].n())
            % all_keys[i].n();
        c_arr[(i + 1) % n] = hash(&crpe, &ch_pi_mul_r);
        i = (i + 1) % n;
    }
    r_arr[signer] = (a * c_arr[signer]
        .modpow(&(skey.n() - &Into::<BigUint>::into(2u32)), skey.n()))
    .modpow(skey.d(), skey.n())
        * skey.primes()[1].clone()
        % skey.n();

    todo!();
}

#[test]
fn test_correct_signature() {
    let mut ctx = Context::default();
    let loader = Loader::default();
    let verifier_bin = loader.load_binary("ring-signature-verify");
    let script_out_point = ctx.deploy_cell(verifier_bin);
    let state = prepare(&mut ctx);
}
