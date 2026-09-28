//! The header-level proof-of-work check, and the mining loop.

use null_protocol::block::{BlockHeader, PowSolution};
use null_protocol::consensus::POW_SOLUTION_LEN;
use rand_core::{CryptoRng, RngCore};

use crate::equihash::{Equihash, Params};
use crate::target::Target;
use crate::Error;

/// Equihash proof of work bound to one parameter set.
#[derive(Clone, Copy, Debug)]
pub struct EquihashPow {
    equihash: Equihash,
}

impl EquihashPow {
    /// Proof of work with our personalization.
    pub fn new(params: Params) -> Self {
        Self {
            equihash: Equihash::new(params),
        }
    }

    /// Length of the meaningful prefix of the solution field.
    fn solution_len(&self) -> usize {
        self.equihash.params().solution_len()
    }

    /// Checks the solution and the target of `header`.
    ///
    /// The solution field is fixed-size; only its first `solution_len`
    /// bytes are the Equihash solution and the rest must be zero.
    ///
    /// # Errors
    /// Returns an Equihash error, [`Error::InvalidTarget`] or
    /// [`Error::InvalidHeader`] if the hash misses the target.
    pub fn check(&self, header: &BlockHeader) -> Result<(), Error> {
        let bytes = header.solution.as_bytes();
        let (solution, padding) = bytes.split_at(self.solution_len().min(POW_SOLUTION_LEN));
        if padding.iter().any(|b| *b != 0) {
            return Err(Error::InvalidHeader("solution padding is not zero"));
        }
        self.equihash
            .verify(&header.pow_input(), &header.nonce, solution)?;
        if Target::from_compact(header.target)?.is_met_by(&header.hash()) {
            Ok(())
        } else {
            Err(Error::InvalidHeader("hash does not meet the target"))
        }
    }

    /// Tries the header's current nonce: solves the puzzle and installs the
    /// first solution whose header hash meets the target.
    ///
    /// # Errors
    /// Returns [`Error::InvalidTarget`] if the header target is malformed.
    pub fn try_nonce(&self, header: &mut BlockHeader) -> Result<bool, Error> {
        let target = Target::from_compact(header.target)?;
        let input = header.pow_input();
        for solution in self.equihash.solve(&input, &header.nonce) {
            let mut padded = [0u8; POW_SOLUTION_LEN];
            if let Some(slot) = padded.get_mut(..solution.len()) {
                slot.copy_from_slice(&solution);
            }
            header.solution = PowSolution::from_bytes(padded);
            if target.is_met_by(&header.hash()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Mines `header` by trying random nonces, up to `max_nonces` of them.
    ///
    /// # Errors
    /// Returns [`Error::InvalidTarget`] if the header target is malformed.
    pub fn mine(
        &self,
        header: &mut BlockHeader,
        max_nonces: u32,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<bool, Error> {
        for _ in 0..max_nonces {
            rng.fill_bytes(&mut header.nonce);
            if self.try_nonce(header)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use null_crypto::pallas;
    use null_protocol::block::{empty_header, BlockHash};
    use null_protocol::transaction::Anchor;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::params::ChainParams;

    fn header(params: &ChainParams) -> BlockHeader {
        let mut h = empty_header(
            1,
            BlockHash::ZERO,
            Anchor::from_base(pallas::Base::from(1u64)),
        );
        h.target = params.pow_limit.to_compact();
        h
    }

    #[test]
    fn mined_header_checks_and_tampering_fails() {
        let params = ChainParams::test();
        let pow = EquihashPow::new(params.equihash);
        let mut h = header(&params);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        assert!(pow.mine(&mut h, 64, &mut rng).unwrap());
        assert!(pow.check(&h).is_ok());

        let mut wrong_nonce = h.clone();
        wrong_nonce.nonce[0] ^= 1;
        assert!(pow.check(&wrong_nonce).is_err());

        let mut wrong_padding = h.clone();
        let mut bytes = *wrong_padding.solution.as_bytes();
        bytes[POW_SOLUTION_LEN - 1] = 1;
        wrong_padding.solution = PowSolution::from_bytes(bytes);
        assert!(matches!(
            pow.check(&wrong_padding),
            Err(Error::InvalidHeader("solution padding is not zero"))
        ));

        let mut impossible = h.clone();
        impossible.target = 0x0100_0001; // target of 1: no hash meets it
        assert!(pow.check(&impossible).is_err());
    }

    #[test]
    fn empty_solution_is_rejected() {
        let params = ChainParams::test();
        let pow = EquihashPow::new(params.equihash);
        assert!(pow.check(&header(&params)).is_err());
    }
}
