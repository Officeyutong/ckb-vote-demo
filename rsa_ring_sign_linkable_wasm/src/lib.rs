use rsa_ring_sign_linkable::{
    check_size_and_write, create_signature, BigUint, PublicKeyParts, RsaPrivateKey, RsaPublicKey,
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
#[wasm_bindgen]
pub fn create_signature_wasm(
    n: usize,
    pub_keys_e_arr: &[u8],
    pub_keys_n_arr: &[u8],
    priv_key_p: &[u8],
    priv_key_q: &[u8],
    priv_key_d: &[u8],
    signer: usize,
    message: &[u8],
) -> Result<RawSignature, String> {
    let mut pub_keys = Vec::<RsaPublicKey>::new();
    for i in 0..n {
        let e = BigUint::from_bytes_le(&pub_keys_e_arr[i * 4..(i + 1) * 4]);
        let n = BigUint::from_bytes_le(&pub_keys_n_arr[i * 256..(i + 1) * 256]);
        pub_keys.push(
            RsaPublicKey::new(n.clone(), e.clone())
                .map_err(|err| format!("Bad public key (n={}, e={}): {}", n, e, err))?,
        );
    }
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
