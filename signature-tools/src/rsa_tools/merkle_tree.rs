use anyhow::{anyhow, Context};
use rs_merkle::{proof_serializers::DirectHashesOrder, MerkleProof, MerkleTree};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use crate::check_size_and_write;

pub fn create_pubkey_group_hash<T: PublicKeyParts>(keys: &[T]) -> anyhow::Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for entry in keys.iter() {
        check_size_and_write(&mut hasher, entry.n(), 256)
            .with_context(|| anyhow!("Failed to write public key entry n"))?;
        check_size_and_write(&mut hasher, entry.e(), 4)
            .with_context(|| format!("Failed to write public key entry e"))?;
    }
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

/// Create a merkle tree, grouping pubkeys with group_size, returning its root hash
pub fn create_merkle_tree_rsa<T: PublicKeyParts, P: FnMut(usize, &[u8]) -> ()>(
    pub_keys: &[T],
    group_size: usize,
    mut leaf_hash_visitor: Option<P>,
) -> anyhow::Result<MerkleTree<rs_merkle::algorithms::Sha256>> {
    let mut hashes = vec![];
    for (index, chunk) in pub_keys.chunks(group_size).enumerate() {
        let hash = create_pubkey_group_hash(chunk)?;

        if let Some(f) = leaf_hash_visitor.as_mut() {
            f(index, &hash);
        }
        hashes.push(hash.try_into().unwrap());
    }
    let merkle_tree = MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&hashes);
    Ok(merkle_tree)
}

pub fn create_merkle_tree_with_root_hash_rsa<T: PublicKeyParts>(
    pub_keys: &[T],
    group_size: usize,
) -> Result<Vec<u8>, String> {
    let tree = create_merkle_tree_rsa(
        pub_keys,
        group_size,
        Option::<Box<dyn Fn(usize, &[u8]) -> ()>>::None,
    )
    .map_err(|e| format!("Failed to create merkle tree: {:?}", e))?;

    Ok(tree
        .root()
        .ok_or_else(|| String::from("Unable to get merkle tree root"))?
        .to_vec())
}

pub struct MerkleProofResult {
    pub proof: Vec<u8>,
    pub leaf_hash: Vec<u8>,
}

pub fn create_merkle_tree_with_proof_rsa<T: PublicKeyParts>(
    pub_keys: &[T],
    group_size: usize,
    proof_index: usize,
) -> Result<MerkleProofResult, String> {
    let mut leaf_hash = None;

    let tree = create_merkle_tree_rsa(
        pub_keys,
        group_size,
        Some(|idx: usize, val: &[u8]| {
            if idx == proof_index {
                leaf_hash = Some(val.to_vec());
            }
        }),
    )
    .map_err(|e| format!("Failed to create merkle tree: {:?}", e))?;

    // let leaf_hash = tree.
    Ok(MerkleProofResult {
        proof: tree.proof(&[proof_index]).serialize::<DirectHashesOrder>(),
        leaf_hash: leaf_hash.ok_or_else(|| String::from("Bad proof index"))?,
    })
}

pub fn verify_merkle_proof(
    proof: &[u8],
    root_hash: &[u8],
    leaf_index: usize,
    leaf_hash: &[u8],
    leaf_count: usize,
) -> Result<bool, String> {
    let proof = MerkleProof::<rs_merkle::algorithms::Sha256>::from_bytes(&proof)
        .map_err(|e| format!("Failed to parse merkle proof: {}", e))?;
    Ok(proof.verify(
        root_hash
            .try_into()
            .map_err(|e| format!("Invalid length of root hash: {}", e))?,
        &[leaf_index],
        &[leaf_hash
            .try_into()
            .map_err(|e| format!("Invalid length of leaf hash: {}", e))?],
        leaf_count,
    ))
}

#[cfg(test)]
mod tests {
    use rand::{thread_rng, Rng};
    use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
    use rsa::RsaPrivateKey;

    use crate::rsa_tools::merkle_tree::{
        create_merkle_tree_with_proof_rsa, create_merkle_tree_with_root_hash_rsa, MerkleProofResult,
    };

    use super::verify_merkle_proof;

    const N: usize = 40;
    const GROUP_SIZE: usize = 15;

    #[test]
    fn test_merkle_tree() {
        let keys = (0..N)
            .into_par_iter()
            .enumerate()
            .map(|(idx, _)| {
                let mut rng = thread_rng();
                println!("{} generation done", idx);
                RsaPrivateKey::new(&mut rng, 2048).unwrap()
            })
            .collect::<Vec<_>>();
        let mut rng = thread_rng();
        let tree_root = create_merkle_tree_with_root_hash_rsa(&keys, GROUP_SIZE).unwrap();
        let group_count = N.div_ceil(GROUP_SIZE);
        let group_index = rng.gen_range(0..group_count);
        let MerkleProofResult {
            leaf_hash,
            proof: proof_bytes,
        } = create_merkle_tree_with_proof_rsa(&keys, GROUP_SIZE, group_index).unwrap();

        assert!(verify_merkle_proof(
            &proof_bytes,
            &tree_root,
            group_index,
            &leaf_hash,
            group_count
        )
        .unwrap());
    }
}
