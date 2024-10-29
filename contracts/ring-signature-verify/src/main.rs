#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use bnum::BUint;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::WitnessArgsReader, prelude::Reader},
    error::SysError,
    high_level::{load_cell_data, load_witness},
};
use sha2::{Digest, Sha256};
use utils::{add_mod_expand, mul_mod_expand, power_mod};

#[cfg(test)]
extern crate alloc;

#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
ckb_std::default_alloc!(4 * 1024, 3 * 1024 * 1024, 64);

#[cfg(test)]
mod tests;
mod utils;

#[repr(i8)]
#[cfg_attr(test, derive(Debug))]
pub enum VoteError {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    BadSignature,
    BadCandidateId,
    BadCandidateCellFormat,
    BadPublicKeyCellFormat,
    MissingDependency,
    BadWitness,
    Unknown,
}

impl From<SysError> for VoteError {
    fn from(value: SysError) -> Self {
        match value {
            SysError::IndexOutOfBound => VoteError::IndexOutOfBound,
            SysError::ItemMissing => VoteError::ItemMissing,
            SysError::LengthNotEnough(_) => VoteError::LengthNotEnough,
            SysError::Encoding => VoteError::Encoding,
            SysError::Unknown(s) => {
                ckb_std::debug!("Unknown error code {}", s);
                VoteError::Unknown
            }
        }
    }
}

const VOTE_CELL_INDEX: usize = 0;
const PUBLIC_KEY_CELL_DEP_INDEX: usize = 1;
const CANDIDATE_CELL_DEP_INDEX: usize = 0;
const WITNESS_INDEX: usize = 0;
pub fn program_entry() -> i8 {
    ckb_std::debug!("Entered");
    match verify_all() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

fn verify_candidate(candidate_id: &[u8]) -> Result<(), VoteError> {
    // Verify candidate cell data..
    let candidate_cell_data = load_cell_data(CANDIDATE_CELL_DEP_INDEX, Source::CellDep)?;
    let n = u16::from_le_bytes([candidate_cell_data[0], candidate_cell_data[1]]) as usize;
    let mut matched = false;
    for i in 0..n {
        let offset = 2 + i * 104;
        if candidate_id == &candidate_cell_data[offset..offset + 4] {
            matched = true;
            break;
        }
    }
    if !matched {
        return Err(VoteError::BadCandidateId);
    }
    Ok(())
}
type Uint2048 = BUint<32>;
fn sha256_for_integer(num: &Uint2048) -> Uint2048 {
    let mut hasher = Sha256::new();
    for digit in num.digits() {
        hasher.update(unsafe { core::slice::from_raw_parts(digit as *const u64 as *const u8, 8) });
    }
    Uint2048::from_le_slice(&hasher.finalize()).unwrap()
}
fn verify_signature(
    ring_size: usize,
    candidate_id: &[u8],
    public_key_n_array: &[u8],
    public_key_e_array: &[u8],
    signature_c: &[u8],
    signature_r_array: &[u8],
    signature_i: &[u8],
) -> Result<(), VoteError> {
    ckb_std::debug!("verify signature, candidate id = {:?}", candidate_id);
    let mut hasher = Sha256::new();
    hasher.update(candidate_id);
    for i in 0..ring_size {
        hasher.update(&public_key_n_array[256 * i..256 * (i + 1)]);
        hasher.update(&public_key_e_array[4 * i..4 * (i + 1)]);
    }
    let compund_hash = |integer1: &Uint2048, integer2: &Uint2048| -> Uint2048 {
        let mut local_hasher = hasher.clone();
        for digit in integer1.digits().iter().chain(integer2.digits().iter()) {
            local_hasher.update(unsafe {
                core::slice::from_raw_parts(digit as *const u64 as *const u8, 8)
            });
        }
        Uint2048::from_le_slice(&local_hasher.finalize()).unwrap()
    };
    let c0 = Uint2048::from_le_slice(signature_c).unwrap();
    let mut last_c = c0;
    let image = Uint2048::from_le_slice(signature_i).unwrap();
    for i in 0..ring_size {
        let r = Uint2048::from_le_slice(&signature_r_array[i * 256..(i + 1) * 256]).unwrap();

        let e_bytes = &public_key_e_array[i * 4..(i + 1) * 4];
        let e = u32::from_le_bytes([e_bytes[0], e_bytes[1], e_bytes[2], e_bytes[3]]);

        let n = Uint2048::from_le_slice(&public_key_n_array[i * 256..(i + 1) * 256]).unwrap();

        let r_power_e = power_mod::<32, 64>(r, e.into(), n);
        let c_mul_r_power_e = mul_mod_expand::<32, 64>(last_c, r_power_e, n);
        let ch_pi_mul_r = mul_mod_expand::<32, 64>(
            add_mod_expand::<32, 33>(
                mul_mod_expand::<32, 64>(last_c, sha256_for_integer(&n), n),
                image,
                n,
            ),
            r_power_e,
            n,
        );
        last_c = compund_hash(&c_mul_r_power_e, &ch_pi_mul_r);
    }
    if last_c != c0 {
        return Err(VoteError::BadSignature);
    }
    Ok(())
}

fn verify_all() -> Result<(), VoteError> {
    let public_key_cell_data = load_cell_data(PUBLIC_KEY_CELL_DEP_INDEX, Source::CellDep)?;
    let ring_size = u16::from_le_bytes([public_key_cell_data[0], public_key_cell_data[1]]) as usize;
    ckb_std::debug!("ring_size={}", ring_size);
    let vote_cell_data = load_cell_data(VOTE_CELL_INDEX, Source::Output)?;
    verify_candidate(&vote_cell_data[0..4])?;
    ckb_std::debug!("candidate verified");
    let witness_data = load_witness(WITNESS_INDEX, Source::Output)?;
    let witness_reader = WitnessArgsReader::from_slice(&witness_data).map_err(|e| {
        ckb_std::debug!("Failed to read witness: {}", e);
        VoteError::BadWitness
    })?;
    let output_type_witness = witness_reader
        .output_type()
        .to_opt()
        .ok_or(VoteError::MissingDependency)?
        .raw_data();

    verify_signature(
        ring_size,
        &vote_cell_data[0..4],
        &public_key_cell_data[2..2 + 256 * ring_size],
        &public_key_cell_data[2 + 256 * ring_size..],
        &output_type_witness[0..256],
        &output_type_witness[256..256 + 256 * ring_size],
        &vote_cell_data[4..4 + 256],
    )?;
    ckb_std::debug!("signature verified");
    Ok(())
}
