use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use signature_tools::{
    check_size_and_write,
    rsa_tools::{
        create_signature,
        merkle_tree::{create_merkle_tree_with_proof_rsa, create_merkle_tree_with_root_hash_rsa},
        PrivateKeyParts, PublicKeyParts, RsaPrivateKey, RsaPublicKey,
    },
    BigUint,
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(getter_with_clone)]
pub struct RawSignature {
    pub c: Vec<u8>,
    pub i: Vec<u8>,
    pub r_arr: Vec<u8>,
    pub e_arr: Vec<u8>,
    pub n_arr: Vec<u8>,
}

fn ensure_size(a: BigUint, expected_size: usize) -> Vec<u8> {
    let mut x = a.to_bytes_le();
    x.resize(expected_size, 0);
    return x;
}
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

}

fn parse_pubkey_entries_from_raw_buf(
    n: usize,
    e_arr: &[u8],
    n_arr: &[u8],
) -> Result<Vec<RsaPublicKey>, String> {
    let mut pub_keys = Vec::<RsaPublicKey>::new();
    for i in 0..n {
        let e = BigUint::from_bytes_le(&e_arr[i * 4..(i + 1) * 4]);
        let n = BigUint::from_bytes_le(&n_arr[i * 256..(i + 1) * 256]);
        pub_keys.push(
            RsaPublicKey::new(n.clone(), e.clone())
                .map_err(|err| format!("Bad public key (n={}, e={}): {}", n, e, err))?,
        );
    }
    Ok(pub_keys)
}

#[wasm_bindgen]
pub fn create_ring_signature_rsa_wasm(
    n: usize,
    pub_keys_e_arr: &[u8],
    pub_keys_n_arr: &[u8],
    priv_key_p: &[u8],
    priv_key_q: &[u8],
    priv_key_d: &[u8],
    signer: usize,
    message: &[u8],
) -> Result<RawSignature, String> {
    let pub_keys = parse_pubkey_entries_from_raw_buf(n, pub_keys_e_arr, pub_keys_n_arr)?;

    let signer_pub_key = &pub_keys[signer];
    let private_key = RsaPrivateKey::from_components(
        signer_pub_key.n().clone(),
        signer_pub_key.e().clone(),
        BigUint::from_bytes_le(priv_key_d),
        vec![
            BigUint::from_bytes_le(priv_key_p),
            BigUint::from_bytes_le(priv_key_q),
        ],
    )
    .map_err(|e| format!("Bad private key: {}", e))?;
    let signature = create_signature(&pub_keys, &private_key, signer, message)
        .map_err(|e| format!("Unable to sign: {}", e))?;

    let result = {
        let mut r_bytes = vec![0u8; 0];
        let mut e_bytes = vec![0u8; 0];
        let mut n_bytes = vec![0u8; 0];

        for item in signature.r_and_pubkey.into_iter() {
            check_size_and_write(&mut r_bytes, &item.r, 256)
                .map_err(|e| format!("Failed to write: {}", e))?;
            check_size_and_write(&mut e_bytes, &item.e, 4)
                .map_err(|e| format!("Failed to write: {}", e))?;
            check_size_and_write(&mut n_bytes, &item.n, 256)
                .map_err(|e| format!("Failed to write: {}", e))?;
        }
        RawSignature {
            c: ensure_size(signature.c, 256),
            i: ensure_size(signature.i, 256),
            r_arr: r_bytes,
            e_arr: e_bytes,
            n_arr: n_bytes,
        }
    };
    Ok(result)
}

#[wasm_bindgen(getter_with_clone)]
/**
 * Numbers are in little endian
 */
pub struct RsaKeyPair {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub d: Vec<u8>,
}

#[wasm_bindgen]
pub fn derive_rsa_key_pair_form_rand_seed(seed: &[u8]) -> Result<RsaKeyPair, String> {
    if seed.len() != 32 {
        return Err(String::from("Seed must be in 32bytes"));
    }
    let mut seed_fixed = [0u8; 32];
    seed_fixed.copy_from_slice(seed);
    let mut rng = ChaCha20Rng::from_seed(seed_fixed);
    let privkey = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("Failed to generate key pair: {}", e))?;
    Ok(RsaKeyPair {
        n: privkey.n().to_bytes_le(),
        e: privkey.e().to_bytes_le(),
        p: privkey
            .primes()
            .get(0)
            .ok_or_else(|| format!("Missing first prime number"))?
            .to_bytes_le(),
        q: privkey
            .primes()
            .get(1)
            .ok_or_else(|| format!("Missing second prime number"))?
            .to_bytes_le(),
        d: privkey.d().to_bytes_le(),
    })
}

pub fn create_merkle_tree_root_rsa(
    n: usize,
    group_size: usize,
    n_arr: &[u8],
    e_arr: &[u8],
) -> Result<Vec<u8>, String> {
    let pub_keys = parse_pubkey_entries_from_raw_buf(n, e_arr, n_arr)?;

    let root = create_merkle_tree_with_root_hash_rsa(&pub_keys, group_size)
        .map_err(|e| format!("{:?}", e))?;
    Ok(root)
}

#[wasm_bindgen(getter_with_clone)]
pub struct MerkleProofResultWasm {
    pub proof: Vec<u8>,
    pub leaf_hash: Vec<u8>,
}
pub fn create_merkle_tree_proof_rsa(
    n: usize,
    group_size: usize,
    n_arr: &[u8],
    e_arr: &[u8],
    leaf_index: usize,
) -> Result<MerkleProofResultWasm, String> {
    let pub_keys = parse_pubkey_entries_from_raw_buf(n, e_arr, n_arr)?;

    let result = create_merkle_tree_with_proof_rsa(&pub_keys, group_size, leaf_index)
        .map_err(|e| format!("{:?}", e))?;
    Ok(MerkleProofResultWasm {
        proof: result.proof,
        leaf_hash: result.leaf_hash,
    })
}
