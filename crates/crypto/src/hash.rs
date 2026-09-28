//! Domain-separated hashing.
//!
//! Every hash in the system goes through this module so that personalization
//! strings are defined exactly once and never reused across purposes.

use blake2b_simd::Params;
use ff::FromUniformBytes;
use pasta_curves::pallas;

/// Length in bytes of a `BLAKE2b` personalization string.
pub const PERSONALIZATION_LEN: usize = 16;

/// Length in bytes of the wide hash output used for unbiased field sampling.
pub const WIDE_OUTPUT_LEN: usize = 64;

/// Length in bytes of the short hash output used for symmetric keys.
pub const SHORT_OUTPUT_LEN: usize = 32;

/// A hash domain, i.e. a `BLAKE2b` personalization string.
///
/// Constructing one is only possible through the constants in this module,
/// which keeps every domain separation string in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Domain(&'static [u8; PERSONALIZATION_LEN]);

impl Domain {
    /// The raw personalization bytes.
    pub fn as_bytes(self) -> &'static [u8; PERSONALIZATION_LEN] {
        self.0
    }
}

/// `PRF^expand`: expands a 32-byte secret and a tag into 64 pseudorandom bytes.
pub const PRF_EXPAND: Domain = Domain(b"null_ExpandSeed_");
/// Derivation of the outgoing viewing key from the full viewing key.
pub const OVK: Domain = Domain(b"null_OvkDerive__");
/// Key derivation for note encryption from the shared secret.
pub const NOTE_KDF: Domain = Domain(b"null_NoteEncKDF_");
/// Derivation of the outgoing cipher key from the outgoing viewing key.
pub const OCK: Domain = Domain(b"null_DeriveOck__");
/// Derivation of the diversifier key from the full viewing key.
pub const DK: Domain = Domain(b"null_DkDerive___");
/// Master key derivation from a seed.
pub const ZIP32_MASTER: Domain = Domain(b"null_IP32Master_");
/// Transaction identifier over the effecting data.
pub const TXID: Domain = Domain(b"null_TxIdHash___");
/// Signature message over the effecting data.
pub const SIGHASH: Domain = Domain(b"null_TxSigHash__");
/// Pinning of build artifacts such as verifying keys. Not a protocol hash.
pub const PIN: Domain = Domain(b"null_ArtifactPin");
/// Block identifier over the header bytes.
pub const BLOCK_HASH: Domain = Domain(b"null_BlockHash__");
/// Commitment to the transactions of a block.
pub const TX_ROOT: Domain = Domain(b"null_TxRoot_____");
/// Digest of the consensus rules a chain database was built under.
pub const RULES: Domain = Domain(b"null_RulesDigest");

/// Hashes the concatenation of `inputs` under `domain` into `length` bytes.
fn blake2b(domain: Domain, length: usize, inputs: &[&[u8]]) -> blake2b_simd::Hash {
    let mut state = Params::new()
        .hash_length(length)
        .personal(domain.as_bytes())
        .to_state();
    for input in inputs {
        state.update(input);
    }
    state.finalize()
}

/// Hashes the concatenation of `inputs` under `domain` into 64 bytes.
pub fn blake2b_wide(domain: Domain, inputs: &[&[u8]]) -> [u8; WIDE_OUTPUT_LEN] {
    *blake2b(domain, WIDE_OUTPUT_LEN, inputs).as_array()
}

/// Hashes the concatenation of `inputs` under `domain` into 32 bytes.
pub fn blake2b_short(domain: Domain, inputs: &[&[u8]]) -> [u8; SHORT_OUTPUT_LEN] {
    let mut out = [0u8; SHORT_OUTPUT_LEN];
    // The output length is fixed by `hash_length`, so the lengths always match.
    out.copy_from_slice(blake2b(domain, SHORT_OUTPUT_LEN, inputs).as_bytes());
    out
}

/// `PRF^expand(sk, t)`: 64 pseudorandom bytes from a secret and a tag.
pub fn prf_expand(secret: &[u8; 32], tag: &[u8]) -> [u8; WIDE_OUTPUT_LEN] {
    blake2b_wide(PRF_EXPAND, &[secret, tag])
}

/// Hashes `inputs` under `domain` to a uniformly distributed base field element.
pub fn hash_to_base(domain: Domain, inputs: &[&[u8]]) -> pallas::Base {
    pallas::Base::from_uniform_bytes(&blake2b_wide(domain, inputs))
}

/// Hashes `inputs` under `domain` to a uniformly distributed scalar field element.
pub fn hash_to_scalar(domain: Domain, inputs: &[&[u8]]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(&blake2b_wide(domain, inputs))
}

/// Reduces 64 wide bytes to a base field element.
pub fn wide_to_base(wide: &[u8; WIDE_OUTPUT_LEN]) -> pallas::Base {
    pallas::Base::from_uniform_bytes(wide)
}

/// Reduces 64 wide bytes to a scalar field element.
pub fn wide_to_scalar(wide: &[u8; WIDE_OUTPUT_LEN]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OTHER: Domain = Domain(b"null_TestDomain_");
    const IVK: Domain = Domain(b"null_TestIvk____");

    #[test]
    fn domains_are_sixteen_bytes() {
        for domain in [PRF_EXPAND, OVK, NOTE_KDF, OCK] {
            assert_eq!(domain.as_bytes().len(), PERSONALIZATION_LEN);
        }
    }

    #[test]
    fn hashing_is_deterministic() {
        assert_eq!(
            blake2b_wide(IVK, &[b"a", b"b"]),
            blake2b_wide(IVK, &[b"a", b"b"])
        );
    }

    #[test]
    fn different_domains_give_different_outputs() {
        assert_ne!(blake2b_wide(IVK, &[b"x"]), blake2b_wide(OTHER, &[b"x"]));
    }

    #[test]
    fn input_chunking_does_not_matter() {
        // The hash is over the concatenation, so the split is irrelevant.
        assert_eq!(
            blake2b_wide(IVK, &[b"ab"]),
            blake2b_wide(IVK, &[b"a", b"b"])
        );
    }

    #[test]
    fn short_hash_is_a_distinct_function_from_wide() {
        let short = blake2b_short(IVK, &[b"x"]);
        let wide = blake2b_wide(IVK, &[b"x"]);
        assert_eq!(short.len(), SHORT_OUTPUT_LEN);
        // BLAKE2b mixes the output length into the parameter block.
        assert_ne!(&wide[..SHORT_OUTPUT_LEN], &short[..]);
    }

    #[test]
    fn prf_expand_separates_tags() {
        let sk = [7u8; 32];
        assert_ne!(prf_expand(&sk, &[0]), prf_expand(&sk, &[1]));
    }

    #[test]
    fn hash_to_field_matches_wide_reduction() {
        let wide = blake2b_wide(IVK, &[b"z"]);
        assert_eq!(hash_to_base(IVK, &[b"z"]), wide_to_base(&wide));
        assert_eq!(hash_to_scalar(IVK, &[b"z"]), wide_to_scalar(&wide));
    }
}
