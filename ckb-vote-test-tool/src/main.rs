use std::{fs::OpenOptions, io::Write};

use jose_jwk::{Rsa, RsaOptional, RsaPrivate};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey,
};

fn main() {
    let key_counts = 10000;
    let keys = (0..key_counts)
        .into_par_iter()
        .map(|idx| {
            let mut rng = rand::thread_rng();
            let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let jwk_string = serde_json::to_string(&jose_jwk::Key::Rsa(Rsa {
                e: priv_key.e().to_bytes_be().into(),
                n: priv_key.n().to_bytes_be().into(),
                prv: Some(RsaPrivate {
                    d: priv_key.d().to_bytes_be().into(),
                    opt: Some(RsaOptional {
                        p: priv_key.primes()[0].to_bytes_be().into(),
                        q: priv_key.primes()[1].to_bytes_be().into(),
                        dp: priv_key.dp().unwrap().to_bytes_be().into(),
                        dq: priv_key.dq().unwrap().to_bytes_be().into(),
                        qi: priv_key.crt_coefficient().unwrap().to_bytes_be().into(),
                        oth: vec![],
                    }),
                }),
            }))
            .unwrap();
            println!("{} done", idx);
            (priv_key, jwk_string)
        })
        .collect::<Vec<_>>();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .open("./pubkey.txt")
        .unwrap();
    for key in keys.iter() {
        file.write(key.1.as_bytes()).unwrap();
        file.write(b"\n").unwrap();
    }
}
