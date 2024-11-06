use std::io::Write;

use sha2::Digest;
use sha2::Sha256;

pub mod candidate;
pub mod rsa_tools;
pub use rsa::BigUint;
pub fn check_size_and_write(
    out_buf: &mut impl Write,
    number: &BigUint,
    expected_size: usize,
) -> anyhow::Result<()> {
    let mut bytes = number.to_bytes_le();
    bytes.resize(expected_size, 0);
    out_buf.write_all(&bytes)?;
    Ok(())
}

fn sha256_for_integer(num: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(num.to_bytes_le());
    BigUint::from_bytes_le(&hasher.finalize())
}
