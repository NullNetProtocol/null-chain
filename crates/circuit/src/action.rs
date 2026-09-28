//! The action circuit: all three layers of `docs/circuit.md`.
//!
//! Public inputs, one instance column, rows in this order:
//! `anchor, nf_old, rk.x, rk.y, cmx_new, cv_net.x, cv_net.y`.

use group::Group;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance};
use null_crypto::commitment::{ValueCommitTrapdoor, ValueCommitment};
use null_crypto::curve::Generator;
use null_crypto::merkle::{MerklePath, MERKLE_DEPTH};
use null_crypto::poseidon::{affine_coords, note_commitment};
use pasta_curves::pallas;

use crate::gadgets::ecc::{
    any_coords, coords, EccGadgetConfig, FullBase, ECC_ADVICES, ECC_LAGRANGE,
};
use crate::gadgets::merkle::{position_bits, MerkleConfig};
use crate::gadgets::note::{
    net_witness, CommittedNote, NoteGadgetConfig, NoteValues, NOTE_ADVICES,
};
use crate::gadgets::poseidon::{self, WIDTH};
use crate::gadgets::range::check_value;
use crate::gadgets::witness::Cell;
use crate::Fp;

/// Instance rows.
pub mod rows {
    /// The anchor.
    pub const ANCHOR: usize = 0;
    /// The old nullifier.
    pub const NULLIFIER: usize = 1;
    /// `rk.x`.
    pub const RK_X: usize = 2;
    /// `rk.y`.
    pub const RK_Y: usize = 3;
    /// The new note commitment.
    pub const CMX: usize = 4;
    /// `cv_net.x`.
    pub const CV_X: usize = 5;
    /// `cv_net.y`.
    pub const CV_Y: usize = 6;
    /// Number of rows.
    pub const COUNT: usize = 7;
}

/// `log2` of the number of rows the circuit needs.
pub const K: u32 = 12;

/// The plaintext of a note as the circuit sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteWitness {
    /// Diversified base of the recipient.
    pub g_d: pallas::Point,
    /// Transmission key of the recipient.
    pub pk_d: pallas::Point,
    /// Value in smallest units.
    pub value: u64,
    /// Uniqueness nonce.
    pub rho: Fp,
    /// Nullifier nonce.
    pub psi: Fp,
    /// Commitment trapdoor.
    pub rcm: Fp,
}

impl NoteWitness {
    /// The commitment, computed outside the circuit.
    pub fn commitment(&self) -> Fp {
        note_commitment(
            &self.g_d, &self.pk_d, self.value, &self.rho, &self.psi, &self.rcm,
        )
    }

    fn values(note: &Value<Self>) -> NoteValues {
        NoteValues {
            value: note.map(|n| n.value),
            psi: note.map(|n| n.psi),
            rcm: note.map(|n| n.rcm),
        }
    }
}

/// Everything the prover knows about the spent note and its owner.
#[derive(Clone, Debug)]
pub struct SpendWitness {
    /// The spent note.
    pub note: NoteWitness,
    /// Its path to the anchor. Ignored by the circuit when the value is 0.
    pub path: MerklePath,
    /// The spend validating key `ak`.
    pub ak: pallas::Point,
    /// The nullifier key.
    pub nk: Fp,
    /// The ivk commitment randomness.
    pub rivk: Fp,
    /// The spend authorization randomizer.
    pub alpha: pallas::Scalar,
}

impl SpendWitness {
    /// The nullifier, computed outside the circuit.
    pub fn nullifier(&self) -> Fp {
        null_crypto::poseidon::nullifier(
            &self.nk,
            &self.note.rho,
            &self.note.psi,
            &self.note.commitment(),
        )
    }

    /// `rk = ak + [alpha] G_spend`, computed outside the circuit.
    #[allow(clippy::arithmetic_side_effects)] // group arithmetic is modular
    pub fn rk(&self) -> pallas::Point {
        self.ak + Generator::SpendAuth.point() * self.alpha
    }
}

/// The full private input of one action.
#[derive(Clone, Debug)]
pub struct ActionWitness {
    /// The spend side.
    pub spend: SpendWitness,
    /// The created note.
    pub output: NoteWitness,
    /// The value commitment trapdoor.
    pub rcv: pallas::Scalar,
}

impl ActionWitness {
    /// `cv_net`, computed outside the circuit.
    ///
    /// # Errors
    /// Returns an error if the net value does not fit `i64`, which cannot
    /// happen for values below the supply cap.
    pub fn cv_net(&self) -> Result<pallas::Point, null_crypto::Error> {
        let net = i128::from(self.spend.note.value)
            .checked_sub(i128::from(self.output.value))
            .and_then(|net| i64::try_from(net).ok())
            .ok_or(null_crypto::Error::Internal("net value overflow"))?;
        let cv = ValueCommitment::commit(net, &ValueCommitTrapdoor::from_scalar(self.rcv));
        Ok(*cv.as_point())
    }
}

/// The public inputs of one action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    /// The tree root.
    pub anchor: Fp,
    /// The nullifier of the spent note.
    pub nf_old: Fp,
    /// The randomized verification key.
    pub rk: pallas::Point,
    /// The commitment of the created note.
    pub cmx_new: Fp,
    /// The net value commitment.
    pub cv_net: pallas::Point,
}

impl PublicInputs {
    /// Derives the public inputs from a witness.
    ///
    /// # Errors
    /// Propagates [`ActionWitness::cv_net`] errors.
    pub fn from_witness(anchor: Fp, witness: &ActionWitness) -> Result<Self, null_crypto::Error> {
        Ok(Self {
            anchor,
            nf_old: witness.spend.nullifier(),
            rk: witness.spend.rk(),
            cmx_new: witness.output.commitment(),
            cv_net: witness.cv_net()?,
        })
    }

    /// The single instance column, in row order.
    pub fn to_instance(&self) -> Vec<Vec<Fp>> {
        let (rk_x, rk_y) = affine_coords(&self.rk);
        let (cv_x, cv_y) = affine_coords(&self.cv_net);
        vec![vec![
            self.anchor,
            self.nf_old,
            rk_x,
            rk_y,
            self.cmx_new,
            cv_x,
            cv_y,
        ]]
    }
}

/// Columns and sub-configurations.
#[derive(Clone, Debug)]
pub struct ActionConfig {
    instance: Column<Instance>,
    note: NoteGadgetConfig,
    merkle: MerkleConfig,
    ecc: EccGadgetConfig,
}

/// The action circuit.
#[derive(Clone, Debug, Default)]
pub struct ActionCircuit {
    witness: Value<ActionWitness>,
}

impl ActionCircuit {
    /// A circuit with a known witness, for proving.
    pub fn new(witness: ActionWitness) -> Self {
        Self {
            witness: Value::known(witness),
        }
    }

    fn spend(&self) -> Value<SpendWitness> {
        self.witness.as_ref().map(|w| w.spend.clone())
    }

    fn old_note(&self) -> Value<NoteWitness> {
        self.witness.as_ref().map(|w| w.spend.note)
    }

    fn new_note(&self) -> Value<NoteWitness> {
        self.witness.as_ref().map(|w| w.output)
    }
}

impl Circuit<Fp> for ActionCircuit {
    type Config = ActionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let state: [Column<Advice>; WIDTH] = core::array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let rc_a = core::array::from_fn(|_| meta.fixed_column());
        let rc_b = core::array::from_fn(|_| meta.fixed_column());
        for column in state {
            meta.enable_equality(column);
        }
        let poseidon = poseidon::configure(meta, state, partial_sbox, rc_a, rc_b);

        let note_advices: [Column<Advice>; NOTE_ADVICES] =
            core::array::from_fn(|_| meta.advice_column());
        let note = NoteGadgetConfig::configure(meta, note_advices, poseidon.clone());

        let swap_advices: [Column<Advice>; 5] = core::array::from_fn(|_| meta.advice_column());
        let merkle = MerkleConfig::configure(meta, poseidon.clone(), swap_advices);

        let ecc_advices: [Column<Advice>; ECC_ADVICES] =
            core::array::from_fn(|_| meta.advice_column());
        let lagrange: [Column<Fixed>; ECC_LAGRANGE] = core::array::from_fn(|_| meta.fixed_column());
        let ecc = EccGadgetConfig::configure(meta, ecc_advices, lagrange);

        ActionConfig {
            instance,
            note,
            merkle,
            ecc,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        config.ecc.load_table(&mut layouter)?;
        let old_note = self.spend_side(&config, &mut layouter)?;
        let new_note = self.output_side(&config, &mut layouter, old_note.nf_old.clone())?;
        // 8. both values are 64-bit
        check_value(
            config.ecc.lookup(),
            layouter.namespace(|| "v_old range"),
            &old_note.note.value,
        )?;
        check_value(
            config.ecc.lookup(),
            layouter.namespace(|| "v_new range"),
            &new_note.value,
        )?;
        self.value_commitment(&config, &mut layouter, &old_note.note, &new_note)
    }
}

/// Cells produced by the spend side that later steps need.
struct SpendCells {
    note: CommittedNote,
    nf_old: Cell,
}

impl ActionCircuit {
    /// Constraints 1 to 5 and the non-identity checks of the old note.
    fn spend_side(
        &self,
        config: &ActionConfig,
        layouter: &mut impl Layouter<Fp>,
    ) -> Result<SpendCells, Error> {
        let spend = self.spend();
        let old = self.old_note();

        let g_d_old = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "g_d_old"), old.map(|n| n.g_d))?;
        let pk_d_old = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "pk_d_old"), old.map(|n| n.pk_d))?;
        let ak = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "ak"), spend.as_ref().map(|s| s.ak))?;

        // 1. old note commitment
        let rho_old = config.note.load(
            layouter.namespace(|| "rho_old"),
            "rho_old",
            old.map(|n| n.rho),
        )?;
        let note = config.note.commit(
            layouter.namespace(|| "old note"),
            &coords(&g_d_old).into(),
            &coords(&pk_d_old).into(),
            rho_old,
            NoteWitness::values(&old),
        )?;

        // 2. membership or dummy
        let anchor = config.note.load_instance(
            layouter.namespace(|| "anchor"),
            config.instance,
            rows::ANCHOR,
        )?;
        let bits: [Value<bool>; MERKLE_DEPTH] = core::array::from_fn(|i| {
            spend.as_ref().map(|s| {
                position_bits(s.path.position())
                    .get(i)
                    .copied()
                    .unwrap_or(false)
            })
        });
        let siblings: [Value<Fp>; MERKLE_DEPTH] = core::array::from_fn(|i| {
            spend
                .as_ref()
                .map(|s| s.path.siblings().get(i).copied().unwrap_or(Fp::zero()))
        });
        let root = config.merkle.root(
            layouter.namespace(|| "merkle root"),
            note.cm.clone(),
            &bits,
            &siblings,
        )?;
        config.note.enforce_membership_or_dummy(
            layouter.namespace(|| "membership"),
            &root,
            &anchor,
            &note.value,
        )?;

        // 3. nullifier
        let nk = config.note.load(
            layouter.namespace(|| "nk"),
            "nk",
            spend.as_ref().map(|s| s.nk),
        )?;
        let nf_old =
            config
                .note
                .nullifier(layouter.namespace(|| "nullifier"), nk.clone(), &note)?;
        layouter.constrain_instance(nf_old.cell(), config.instance, rows::NULLIFIER)?;

        // 4. spend authority: pk_d_old = [ivk] g_d_old
        let rivk = config.note.load(
            layouter.namespace(|| "rivk"),
            "rivk",
            spend.as_ref().map(|s| s.rivk),
        )?;
        let (ak_x, _) = coords(&ak);
        let ivk = config
            .note
            .ivk(layouter.namespace(|| "ivk"), ak_x, nk, rivk)?;
        let pk_d_derived =
            config
                .ecc
                .mul_by_base(layouter.namespace(|| "[ivk] g_d"), &ivk, &g_d_old)?;
        pk_d_old.constrain_equal(layouter.namespace(|| "pk_d = [ivk] g_d"), &pk_d_derived)?;

        // 5. rk = ak + [alpha] G_spend
        let alpha_g = config.ecc.mul_fixed(
            layouter.namespace(|| "[alpha] G_spend"),
            FullBase::SpendAuth,
            spend.as_ref().map(|s| s.alpha),
        )?;
        let rk = alpha_g.add(layouter.namespace(|| "rk"), &ak)?;
        constrain_point(config, layouter, &rk, rows::RK_X, rows::RK_Y)?;

        Ok(SpendCells { note, nf_old })
    }

    /// Constraints 6, 7 and the non-identity checks of the new note.
    fn output_side(
        &self,
        config: &ActionConfig,
        layouter: &mut impl Layouter<Fp>,
        nf_old: Cell,
    ) -> Result<CommittedNote, Error> {
        let new = self.new_note();
        let g_d_new = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "g_d_new"), new.map(|n| n.g_d))?;
        let pk_d_new = config
            .ecc
            .witness_non_identity(layouter.namespace(|| "pk_d_new"), new.map(|n| n.pk_d))?;
        let note = config.note.commit(
            layouter.namespace(|| "new note"),
            &coords(&g_d_new).into(),
            &coords(&pk_d_new).into(),
            nf_old,
            NoteWitness::values(&new),
        )?;
        layouter.constrain_instance(note.cm.cell(), config.instance, rows::CMX)?;
        Ok(note)
    }

    /// Constraint 9: `cv_net = [v_old - v_new] V + [rcv] R`.
    fn value_commitment(
        &self,
        config: &ActionConfig,
        layouter: &mut impl Layouter<Fp>,
        old_note: &CommittedNote,
        new_note: &CommittedNote,
    ) -> Result<(), Error> {
        let net = self
            .witness
            .as_ref()
            .map(|w| net_witness(w.spend.note.value, w.output.value));
        let (magnitude, sign) = config.note.net_value(
            layouter.namespace(|| "v_old - v_new"),
            &old_note.value,
            &new_note.value,
            net,
        )?;
        let net_v = config
            .ecc
            .mul_value(layouter.namespace(|| "[v_net] V"), &magnitude, &sign)?;
        let rcv_r = config.ecc.mul_fixed(
            layouter.namespace(|| "[rcv] R"),
            FullBase::ValueCommitRandom,
            self.witness.as_ref().map(|w| w.rcv),
        )?;
        let expected = net_v.add(layouter.namespace(|| "[v_net] V + [rcv] R"), &rcv_r)?;
        let cv_net = config.ecc.witness_point(
            layouter.namespace(|| "cv_net"),
            self.witness
                .as_ref()
                .map(|w| w.cv_net().unwrap_or(pallas::Point::identity())),
        )?;
        cv_net.constrain_equal(layouter.namespace(|| "value balance"), &expected)?;
        constrain_point(config, layouter, &cv_net, rows::CV_X, rows::CV_Y)
    }
}

/// Binds a point's coordinates to two instance rows.
fn constrain_point(
    config: &ActionConfig,
    layouter: &mut impl Layouter<Fp>,
    point: &crate::gadgets::ecc::AnyPoint,
    row_x: usize,
    row_y: usize,
) -> Result<(), Error> {
    let (x, y) = any_coords(point);
    layouter.constrain_instance(x.cell(), config.instance, row_x)?;
    layouter.constrain_instance(y.cell(), config.instance, row_y)
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use halo2_proofs::dev::{MockProver, VerifyFailure};
    use null_crypto::keys::{FullViewingKey, SpendingKey};
    use null_crypto::merkle::MerkleTree;
    use null_crypto::signature::{RandomizedVerificationKey, SpendAuthRandomizer};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    /// A random note owned by nobody in particular.
    fn random_note(rng: &mut ChaCha20Rng, value: u64) -> NoteWitness {
        NoteWitness {
            g_d: pallas::Point::random(&mut *rng),
            pk_d: pallas::Point::random(&mut *rng),
            value,
            rho: Fp::random(&mut *rng),
            psi: Fp::random(&mut *rng),
            rcm: Fp::random(&mut *rng),
        }
    }

    struct Fixture {
        witness: ActionWitness,
        public: PublicInputs,
    }

    /// A real spend by a real key of a note in a tree with other leaves.
    fn fixture(seed: u64, value: u64) -> Fixture {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let sk = SpendingKey::random(&mut rng);
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let ivk = fvk.incoming_viewing_key().unwrap();
        let d = null_crypto::keys::Diversifier::random(&mut rng);
        let g_d = d.base().unwrap();
        let pk_d = *ivk.transmission_key(&d).unwrap().as_point();
        let note = NoteWitness {
            g_d,
            pk_d,
            value,
            rho: Fp::random(&mut rng),
            psi: Fp::random(&mut rng),
            rcm: Fp::random(&mut rng),
        };

        let mut tree = MerkleTree::new();
        tree.append(Fp::random(&mut rng)).unwrap();
        let position = tree.append(note.commitment()).unwrap();
        tree.append(Fp::random(&mut rng)).unwrap();

        let spend = SpendWitness {
            note,
            path: tree.path(position).unwrap(),
            ak: fvk.ak().to_point().unwrap(),
            nk: fvk.nk().expose(),
            rivk: fvk.rivk().expose(),
            alpha: pallas::Scalar::random(&mut rng),
        };
        let mut output = random_note(&mut rng, 5);
        output.rho = spend.nullifier();
        let witness = ActionWitness {
            spend,
            output,
            rcv: pallas::Scalar::random(&mut rng),
        };
        let public = PublicInputs::from_witness(tree.root(), &witness).unwrap();
        Fixture { witness, public }
    }

    fn prove(f: &Fixture, public: &PublicInputs) -> Result<(), Vec<VerifyFailure>> {
        let circuit = ActionCircuit::new(f.witness.clone());
        MockProver::run(K, &circuit, public.to_instance())
            .unwrap()
            .verify()
    }

    fn fails(f: &Fixture, public: &PublicInputs) -> bool {
        let circuit = ActionCircuit::new(f.witness.clone());
        MockProver::run(K, &circuit, public.to_instance()).map_or(true, |p| p.verify().is_err())
    }

    #[test]
    fn instance_has_the_documented_row_count() {
        assert_eq!(fixture(1, 10).public.to_instance()[0].len(), rows::COUNT);
    }

    #[test]
    fn rk_matches_reddsa_randomization() {
        let f = fixture(2, 10);
        let fvk_ak = null_crypto::keys::SpendValidatingKey::from_bytes(
            &null_crypto::encoding::point_to_bytes(&f.witness.spend.ak),
        )
        .unwrap();
        let alpha = SpendAuthRandomizer::from_scalar(f.witness.spend.alpha);
        let rk = RandomizedVerificationKey::new(&fvk_ak, &alpha);
        assert_eq!(
            rk.to_bytes(),
            null_crypto::encoding::point_to_bytes(&f.public.rk)
        );
    }

    #[test]
    fn valid_spend_satisfies_the_circuit() {
        let f = fixture(3, 1_000);
        assert_eq!(prove(&f, &f.public), Ok(()));
    }

    #[test]
    fn dummy_spend_accepts_any_anchor() {
        let f = fixture(4, 0);
        let public = PublicInputs {
            anchor: Fp::from(7),
            ..f.public
        };
        assert_eq!(prove(&f, &public), Ok(()));
    }

    #[test]
    fn wrong_anchor_fails_for_a_real_spend() {
        let f = fixture(5, 1_000);
        assert!(fails(
            &f,
            &PublicInputs {
                anchor: Fp::from(7),
                ..f.public
            }
        ));
    }

    #[test]
    fn wrong_nullifier_fails() {
        let f = fixture(6, 1_000);
        assert!(fails(
            &f,
            &PublicInputs {
                nf_old: f.public.nf_old + Fp::one(),
                ..f.public
            }
        ));
    }

    #[test]
    fn wrong_nullifier_key_breaks_spend_authority() {
        let mut f = fixture(7, 1_000);
        f.witness.spend.nk += Fp::one();
        // nk feeds both the nullifier and ivk; recompute the public nullifier
        // so only the spend authority constraint can fail.
        let public = PublicInputs {
            nf_old: f.witness.spend.nullifier(),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn wrong_rivk_breaks_spend_authority() {
        let mut f = fixture(8, 1_000);
        f.witness.spend.rivk += Fp::one();
        assert!(fails(&f, &f.public));
    }

    #[test]
    fn foreign_ak_breaks_spend_authority_and_rk() {
        let mut f = fixture(9, 1_000);
        f.witness.spend.ak = pallas::Point::random(ChaCha20Rng::seed_from_u64(99));
        let public = PublicInputs {
            rk: f.witness.spend.rk(),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn wrong_rk_fails() {
        let f = fixture(10, 1_000);
        let public = PublicInputs {
            rk: pallas::Point::random(ChaCha20Rng::seed_from_u64(98)),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn wrong_new_commitment_fails() {
        let f = fixture(11, 1_000);
        assert!(fails(
            &f,
            &PublicInputs {
                cmx_new: f.public.cmx_new + Fp::one(),
                ..f.public
            }
        ));
    }

    #[test]
    fn new_note_must_chain_from_the_old_nullifier() {
        let mut f = fixture(12, 1_000);
        f.witness.output.rho += Fp::one();
        let public = PublicInputs {
            cmx_new: f.witness.output.commitment(),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn tampered_path_fails_for_a_real_spend() {
        let mut f = fixture(13, 1_000);
        let mut siblings = *f.witness.spend.path.siblings();
        siblings[3] += Fp::one();
        f.witness.spend.path = MerklePath::new(f.witness.spend.path.position(), siblings);
        assert!(fails(&f, &f.public));
    }

    #[test]
    fn wrong_value_commitment_fails() {
        let f = fixture(14, 1_000);
        let public = PublicInputs {
            cv_net: pallas::Point::random(ChaCha20Rng::seed_from_u64(97)),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn value_commitment_binds_the_values() {
        let mut f = fixture(15, 1_000);
        // Claim a different net value in cv_net than the notes carry.
        let forged = ValueCommitment::commit(
            1_000 - 5 + 1,
            &ValueCommitTrapdoor::from_scalar(f.witness.rcv),
        );
        let public = PublicInputs {
            cv_net: *forged.as_point(),
            ..f.public
        };
        assert!(fails(&f, &public));
        f.witness.rcv += pallas::Scalar::one();
        assert!(fails(&f, &f.public));
    }

    #[test]
    fn identity_points_are_rejected() {
        let mut f = fixture(16, 1_000);
        f.witness.output.g_d = pallas::Point::identity();
        let public = PublicInputs {
            cmx_new: f.witness.output.commitment(),
            ..f.public
        };
        assert!(fails(&f, &public));
    }

    #[test]
    fn cv_net_matches_value_commitment_of_the_difference() {
        let f = fixture(17, 1_000);
        let expected =
            ValueCommitment::commit(995, &ValueCommitTrapdoor::from_scalar(f.witness.rcv));
        assert_eq!(f.public.cv_net, *expected.as_point());
    }

    #[test]
    fn value_commitment_handles_every_sign_of_the_net_value() {
        // Spend more than created, less than created, and the same.
        for (seed, old, new) in [(18u64, 1_000u64, 5u64), (19, 1_000, 2_000), (20, 7, 7)] {
            let mut f = fixture(seed, old);
            f.witness.output.value = new;
            let public = PublicInputs::from_witness(f.public.anchor, &f.witness).unwrap();
            assert_eq!(prove(&f, &public), Ok(()), "old {old} new {new}");
        }
    }

    #[test]
    fn net_value_witness_is_the_signed_difference() {
        assert_eq!(net_witness(10, 3), (7, false));
        assert_eq!(net_witness(3, 10), (7, true));
        assert_eq!(net_witness(4, 4), (0, false));
        assert_eq!(net_witness(0, u64::MAX), (u64::MAX, true));
    }
}
