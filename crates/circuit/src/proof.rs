//! Key generation, proving and verifying for a bundle of actions.
//!
//! One proof covers every action of a transaction: the same circuit is
//! instantiated once per action and Halo2 proves them together. Keys are
//! deterministic functions of the circuit, so every node derives the same
//! keys; the verifying key is pinned by hash in the tests.

use halo2_proofs::plonk::{
    self, create_proof, keygen_pk, keygen_vk, verify_proof, BatchVerifier, SingleVerifier,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use pasta_curves::vesta;
use rand_core::{CryptoRng, RngCore};

use crate::action::{ActionCircuit, ActionWitness, PublicInputs, K};
use crate::{Error, Fp};

/// The commitment scheme parameters, shared by both keys.
fn params() -> Params<vesta::Affine> {
    Params::new(K)
}

/// The exact proof length for a bundle of `actions` actions, or `None` if
/// the count is not an allowed action class. Proof length is a
/// deterministic function of the circuit and the instance count; the
/// values are checked against real proofs in `tests/prove.rs`.
pub fn proof_len(actions: usize) -> Option<usize> {
    match actions {
        2 => Some(8_736),
        4 => Some(14_496),
        8 => Some(26_016),
        16 => Some(49_056),
        _ => None,
    }
}

/// The proving key with its parameters.
#[derive(Debug)]
pub struct ProvingKey {
    params: Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    /// Generates the proving key for the action circuit.
    ///
    /// # Errors
    /// Propagates key generation errors.
    pub fn build() -> Result<Self, Error> {
        let params = params();
        let vk = keygen_vk(&params, &ActionCircuit::default())?;
        let pk = keygen_pk(&params, vk, &ActionCircuit::default())?;
        Ok(Self { params, pk })
    }

    /// The matching verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            params: params(),
            vk: self.pk.get_vk().clone(),
        }
    }
}

/// The verifying key with its parameters.
#[derive(Debug)]
pub struct VerifyingKey {
    params: Params<vesta::Affine>,
    vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    /// Generates the verifying key for the action circuit.
    ///
    /// # Errors
    /// Propagates key generation errors.
    pub fn build() -> Result<Self, Error> {
        let params = params();
        let vk = keygen_vk(&params, &ActionCircuit::default())?;
        Ok(Self { params, vk })
    }

    /// A stable textual description of the circuit and key, for pinning.
    pub fn pinned_description(&self) -> String {
        format!("{:#?}", self.vk.pinned())
    }
}

/// A proof over one or more actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof(Vec<u8>);

impl Proof {
    /// Wraps proof bytes received from the network.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Proves every action. `public` must line up with `witnesses`.
    ///
    /// # Errors
    /// Returns [`Error::CountMismatch`] on unequal or empty inputs, or a
    /// proving system error.
    pub fn create(
        pk: &ProvingKey,
        witnesses: &[ActionWitness],
        public: &[PublicInputs],
        rng: impl RngCore + CryptoRng,
    ) -> Result<Self, Error> {
        if witnesses.is_empty() || witnesses.len() != public.len() {
            return Err(Error::CountMismatch);
        }
        let circuits: Vec<ActionCircuit> =
            witnesses.iter().cloned().map(ActionCircuit::new).collect();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(Vec::new());
        with_instances(public, |instances| {
            create_proof(
                &pk.params,
                &pk.pk,
                &circuits,
                instances,
                rng,
                &mut transcript,
            )
        })?;
        Ok(Self(transcript.finalize()))
    }

    /// Verifies the proof against the public inputs of every action.
    ///
    /// # Errors
    /// Returns [`Error::InvalidProof`] if verification fails.
    pub fn verify(&self, vk: &VerifyingKey, public: &[PublicInputs]) -> Result<(), Error> {
        if public.is_empty() {
            return Err(Error::CountMismatch);
        }
        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript =
            Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(self.0.as_slice());
        with_instances(public, |instances| {
            verify_proof(&vk.params, &vk.vk, strategy, instances, &mut transcript)
        })
        .map_err(|_| Error::InvalidProof)
    }
}

/// Verifies many proofs at once, amortizing the expensive part of
/// verification across a block.
pub struct ProofBatch {
    inner: BatchVerifier<vesta::Affine>,
    count: usize,
}

impl ProofBatch {
    /// An empty batch.
    pub fn new() -> Self {
        Self {
            inner: BatchVerifier::new(),
            count: 0,
        }
    }

    /// Number of queued proofs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Queues a proof with the public inputs of its actions.
    ///
    /// # Errors
    /// Returns [`Error::CountMismatch`] on empty public inputs.
    pub fn add(&mut self, proof: &Proof, public: &[PublicInputs]) -> Result<(), Error> {
        if public.is_empty() {
            return Err(Error::CountMismatch);
        }
        let instances = public.iter().map(PublicInputs::to_instance).collect();
        self.inner.add_proof(instances, proof.as_bytes().to_vec());
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    /// Verifies everything queued. An empty batch verifies trivially.
    ///
    /// # Errors
    /// Returns [`Error::InvalidProof`] if any queued proof is wrong; the
    /// batch does not say which one.
    pub fn verify(self, vk: &VerifyingKey) -> Result<(), Error> {
        if self.inner.finalize(&vk.params, &vk.vk) {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        }
    }
}

impl Default for ProofBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ProofBatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProofBatch")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// Builds the nested instance slices Halo2 borrows and runs `f` on them.
fn with_instances<R>(public: &[PublicInputs], f: impl FnOnce(&[&[&[Fp]]]) -> R) -> R {
    let owned: Vec<Vec<Vec<Fp>>> = public.iter().map(PublicInputs::to_instance).collect();
    let columns: Vec<Vec<&[Fp]>> = owned
        .iter()
        .map(|circuit| circuit.iter().map(Vec::as_slice).collect())
        .collect();
    let circuits: Vec<&[&[Fp]]> = columns.iter().map(Vec::as_slice).collect();
    f(&circuits)
}

#[cfg(test)]
mod tests {
    use null_crypto::hash::{blake2b_short, PIN};

    use super::*;

    /// `BLAKE2b` of the pinned verifying key description. Any change to the
    /// circuit changes this value; update it deliberately, never casually.
    const PINNED_VK_HASH: &str = "1695a41f021d6d96f2c6370f758ebc280b3caa9652bb60e9cb48fee4148a6f13";

    #[test]
    fn verifying_key_is_pinned() {
        let vk = VerifyingKey::build().unwrap();
        let digest = blake2b_short(PIN, &[vk.pinned_description().as_bytes()]);
        let hex = null_crypto::encoding::to_hex(&digest);
        assert_eq!(
            hex, PINNED_VK_HASH,
            "verifying key changed; see docs/circuit.md before updating"
        );
    }

    #[test]
    fn proof_len_covers_exactly_the_action_classes() {
        for (class, len) in [(2, 8_736), (4, 14_496), (8, 26_016), (16, 49_056)] {
            assert_eq!(proof_len(class), Some(len));
        }
        for other in [0, 1, 3, 5, 17, 32] {
            assert_eq!(proof_len(other), None);
        }
    }

    #[test]
    fn empty_batch_verifies_and_rejects_empty_inputs() {
        let vk = VerifyingKey::build().unwrap();
        let mut batch = ProofBatch::new();
        assert!(batch.is_empty());
        assert!(matches!(
            batch.add(&Proof::from_bytes(vec![]), &[]),
            Err(Error::CountMismatch)
        ));
        assert!(batch.verify(&vk).is_ok());
    }

    #[test]
    fn proof_bytes_roundtrip() {
        let proof = Proof::from_bytes(vec![1, 2, 3]);
        assert_eq!(proof.as_bytes(), &[1, 2, 3]);
    }
}
