use std::array;
use std::convert::{TryFrom, TryInto};

use crate::penumbra::parallel_utils::{flatten_results, transform, transform_parallel};
use crate::penumbra::single::{
    self, circuit_degree, group::F, log::ContributionHash, DLogProof, ExtraTransitionInformation, LinkingProof,
    Phase1CRSElements, Phase1Contribution, Phase1RawCRSElements, Phase1RawContribution, Phase2CRSElements,
    Phase2Contribution, Phase2RawCRSElements, Phase2RawContribution,
};
use anyhow::{anyhow, Result};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use decaf377::Bls12_377;

use crate::penumbra::proto::tools::summoning::v1alpha1::{self as pb};

use rand_core::OsRng;

// Some helper functions since we have to use these seventeen billion times

fn to_bytes<T: CanonicalSerialize>(t: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    t.serialize_uncompressed(&mut out)?;
    Ok(out)
}

fn from_bytes<T: CanonicalDeserialize>(data: &[u8]) -> Result<T> {
    Ok(T::deserialize_uncompressed(data)?)
}

fn from_bytes_unchecked<T: CanonicalDeserialize>(data: &[u8]) -> Result<T> {
    Ok(T::deserialize_uncompressed_unchecked(data)?)
}

pub const NUM_CIRCUITS: usize = 7;

pub fn circuit_sizes() -> [usize; NUM_CIRCUITS] {
    [0x10_000, 0x4_000, 0x10_000, 0x4_000, 0x8_000, 0x10_000, 0x200]
}

/// Holds all of the CRS elements for phase2 in one struct, before validation.
#[derive(Clone, Debug)]
pub struct Phase2RawCeremonyCRS([Phase2RawCRSElements; NUM_CIRCUITS]);

impl Phase2RawCeremonyCRS {
    /// Skip validation, performing the conversion anyways.
    ///
    /// Useful when parsing known good data.
    pub fn assume_valid(self) -> Phase2CeremonyCRS {
        match self.0 {
            [x0, x1, x2, x3, x4, x5, x6] => Phase2CeremonyCRS([
                x0.assume_valid(),
                x1.assume_valid(),
                x2.assume_valid(),
                x3.assume_valid(),
                x4.assume_valid(),
                x5.assume_valid(),
                x6.assume_valid(),
            ]),
        }
    }

    pub fn unchecked_from_protobuf(value: pb::CeremonyCrs) -> anyhow::Result<Self> {
        Ok(Self([
            from_bytes_unchecked::<Phase2RawCRSElements>(value.spend.as_slice())?,
            from_bytes_unchecked::<Phase2RawCRSElements>(value.output.as_slice())?,
            from_bytes_unchecked::<Phase2RawCRSElements>(value.delegator_vote.as_slice())?,
            from_bytes_unchecked::<Phase2RawCRSElements>(value.undelegate_claim.as_slice())?,
            from_bytes_unchecked::<Phase2RawCRSElements>(value.swap.as_slice())?,
            from_bytes_unchecked::<Phase2RawCRSElements>(value.swap_claim.as_slice())?,
            from_bytes_unchecked::<Phase2RawCRSElements>(value.nullifer_derivation_crs.as_slice())?,
        ]))
    }
}

impl TryInto<pb::CeremonyCrs> for Phase2RawCeremonyCRS {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<pb::CeremonyCrs> {
        Ok(pb::CeremonyCrs {
            spend: to_bytes(&self.0[0])?,
            output: to_bytes(&self.0[1])?,
            delegator_vote: to_bytes(&self.0[2])?,
            undelegate_claim: to_bytes(&self.0[3])?,
            swap: to_bytes(&self.0[4])?,
            swap_claim: to_bytes(&self.0[5])?,
            nullifer_derivation_crs: to_bytes(&self.0[6])?,
        })
    }
}

impl TryFrom<pb::CeremonyCrs> for Phase2RawCeremonyCRS {
    type Error = anyhow::Error;

    fn try_from(value: pb::CeremonyCrs) -> std::result::Result<Self, Self::Error> {
        Ok(Self([
            from_bytes::<Phase2RawCRSElements>(value.spend.as_slice())?,
            from_bytes::<Phase2RawCRSElements>(value.output.as_slice())?,
            from_bytes::<Phase2RawCRSElements>(value.delegator_vote.as_slice())?,
            from_bytes::<Phase2RawCRSElements>(value.undelegate_claim.as_slice())?,
            from_bytes::<Phase2RawCRSElements>(value.swap.as_slice())?,
            from_bytes::<Phase2RawCRSElements>(value.swap_claim.as_slice())?,
            from_bytes::<Phase2RawCRSElements>(value.nullifer_derivation_crs.as_slice())?,
        ]))
    }
}

/// Holds all of the CRS elements for phase2 in one struct.
#[derive(Clone, Debug)]
pub struct Phase2CeremonyCRS([Phase2CRSElements; NUM_CIRCUITS]);

impl From<Phase2CeremonyCRS> for Phase2RawCeremonyCRS {
    fn from(value: Phase2CeremonyCRS) -> Self {
        Self(array::from_fn(|i| value.0[i].raw.clone()))
    }
}

impl TryFrom<Phase2CeremonyCRS> for pb::CeremonyCrs {
    type Error = anyhow::Error;

    fn try_from(data: Phase2CeremonyCRS) -> Result<pb::CeremonyCrs> {
        Phase2RawCeremonyCRS::from(data).try_into()
    }
}

/// All phase2 contributions, before they've been validated.
#[derive(Clone, Debug)]
pub struct Phase2RawCeremonyContribution([Phase2RawContribution; NUM_CIRCUITS]);

impl TryInto<pb::participate_request::Contribution> for Phase2RawCeremonyContribution {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<pb::participate_request::Contribution> {
        Ok(pb::participate_request::Contribution {
            updated: Some(pb::CeremonyCrs {
                spend: to_bytes(&self.0[0].new_elements)?,
                output: to_bytes(&self.0[1].new_elements)?,
                delegator_vote: to_bytes(&self.0[2].new_elements)?,
                undelegate_claim: to_bytes(&self.0[3].new_elements)?,
                swap: to_bytes(&self.0[4].new_elements)?,
                swap_claim: to_bytes(&self.0[5].new_elements)?,
                nullifer_derivation_crs: to_bytes(&self.0[6].new_elements)?,
            }),
            update_proofs: Some(pb::CeremonyLinkingProof {
                spend: to_bytes(&self.0[0].linking_proof)?,
                output: to_bytes(&self.0[1].linking_proof)?,
                delegator_vote: to_bytes(&self.0[2].linking_proof)?,
                undelegate_claim: to_bytes(&self.0[3].linking_proof)?,
                swap: to_bytes(&self.0[4].linking_proof)?,
                swap_claim: to_bytes(&self.0[5].linking_proof)?,
                nullifer_derivation_crs: to_bytes(&self.0[6].linking_proof)?,
            }),
            parent_hashes: Some(pb::CeremonyParentHashes {
                spend: self.0[0].parent.0.to_vec(),
                output: self.0[1].parent.0.to_vec(),
                delegator_vote: self.0[2].parent.0.to_vec(),
                undelegate_claim: self.0[3].parent.0.to_vec(),
                swap: self.0[4].parent.0.to_vec(),
                swap_claim: self.0[5].parent.0.to_vec(),
                nullifer_derivation_crs: self.0[6].parent.0.to_vec(),
            }),
        })
    }
}

impl TryFrom<pb::participate_request::Contribution> for Phase2RawCeremonyContribution {
    type Error = anyhow::Error;

    fn try_from(value: pb::participate_request::Contribution) -> Result<Self> {
        let (parent_hashes, updated, update_proofs) = match value {
            pb::participate_request::Contribution {
                parent_hashes: Some(x0),
                updated: Some(x1),
                update_proofs: Some(x2),
            } => (x0, x1, x2),
            _ => anyhow::bail!("missing contribution data"),
        };
        let data = [
            (parent_hashes.spend, updated.spend, update_proofs.spend),
            (parent_hashes.output, updated.output, update_proofs.output),
            (
                parent_hashes.delegator_vote,
                updated.delegator_vote,
                update_proofs.delegator_vote,
            ),
            (
                parent_hashes.undelegate_claim,
                updated.undelegate_claim,
                update_proofs.undelegate_claim,
            ),
            (parent_hashes.swap, updated.swap, update_proofs.swap),
            (parent_hashes.swap_claim, updated.swap_claim, update_proofs.swap_claim),
            (
                parent_hashes.nullifer_derivation_crs,
                updated.nullifer_derivation_crs,
                update_proofs.nullifer_derivation_crs,
            ),
        ];
        let out = transform_parallel(data, |(parent_hash, updated, update_proof)| {
            Ok::<_, anyhow::Error>(Phase2RawContribution {
                parent: ContributionHash::try_from(parent_hash.as_slice())?,
                new_elements: from_bytes::<Phase2RawCRSElements>(updated.as_slice())?,
                linking_proof: from_bytes::<DLogProof>(update_proof.as_slice())?,
            })
        });
        Ok(Self(flatten_results(out)?))
    }
}

impl Phase2RawCeremonyContribution {
    /// Validate that this contribution is internally consistent.
    ///
    /// This doesn't check that it's connected to the right parent though, which is an additional
    /// step you want to do.
    pub fn validate(self, root: &Phase2CeremonyCRS) -> Option<Phase2CeremonyContribution> {
        let data: [_; 7] = self
            .0
            .into_iter()
            .zip(root.0.iter())
            .collect::<Vec<_>>()
            .try_into()
            .expect("iterator should have the same size");
        let out = transform_parallel(data, |(x, root)| {
            x.validate(&mut OsRng, root).ok_or(anyhow!("failed to validate"))
        });
        Some(Phase2CeremonyContribution(flatten_results(out).ok()?))
    }

    /// Skip validation, performing the conversion anyways.
    ///
    /// Useful when parsing known good data.
    pub fn assume_valid(self) -> Phase2CeremonyContribution {
        // This avoids a copy, and will break if we change the size:
        Phase2CeremonyContribution(transform(self.0, |x| x.assume_valid()))
    }

    pub fn unchecked_from_protobuf(value: pb::participate_request::Contribution) -> Result<Self> {
        let (parent_hashes, updated, update_proofs) = match value {
            pb::participate_request::Contribution {
                parent_hashes: Some(x0),
                updated: Some(x1),
                update_proofs: Some(x2),
            } => (x0, x1, x2),
            _ => anyhow::bail!("missing contribution data"),
        };
        let data = [
            (parent_hashes.spend, updated.spend, update_proofs.spend),
            (parent_hashes.output, updated.output, update_proofs.output),
            (
                parent_hashes.delegator_vote,
                updated.delegator_vote,
                update_proofs.delegator_vote,
            ),
            (
                parent_hashes.undelegate_claim,
                updated.undelegate_claim,
                update_proofs.undelegate_claim,
            ),
            (parent_hashes.swap, updated.swap, update_proofs.swap),
            (parent_hashes.swap_claim, updated.swap_claim, update_proofs.swap_claim),
            (
                parent_hashes.nullifer_derivation_crs,
                updated.nullifer_derivation_crs,
                update_proofs.nullifer_derivation_crs,
            ),
        ];
        let out = transform(data, |(parent_hash, updated, update_proof)| {
            Ok::<_, anyhow::Error>(Phase2RawContribution {
                parent: ContributionHash::try_from(parent_hash.as_slice())?,
                new_elements: from_bytes_unchecked::<Phase2RawCRSElements>(updated.as_slice())?,
                linking_proof: from_bytes_unchecked::<DLogProof>(update_proof.as_slice())?,
            })
        });
        Ok(Self(flatten_results(out)?))
    }
}

/// Holds all of the phase2 contributions in a single package.
#[derive(Clone, Debug)]
pub struct Phase2CeremonyContribution([Phase2Contribution; NUM_CIRCUITS]);

impl From<Phase2CeremonyContribution> for Phase2RawCeremonyContribution {
    fn from(value: Phase2CeremonyContribution) -> Self {
        let out: [Phase2RawContribution; NUM_CIRCUITS] =
            array::from_fn(|i| Phase2RawContribution::from(value.0[i].clone()));
        Self(out)
    }
}

impl TryFrom<Phase2CeremonyContribution> for pb::participate_request::Contribution {
    type Error = anyhow::Error;

    fn try_from(data: Phase2CeremonyContribution) -> Result<pb::participate_request::Contribution> {
        Phase2RawCeremonyContribution::from(data).try_into()
    }
}

impl Phase2CeremonyContribution {
    /// Get the new elements contained in this contribution
    pub fn new_elements(&self) -> Phase2CeremonyCRS {
        Phase2CeremonyCRS(array::from_fn(|i| self.0[i].new_elements.clone()))
    }

    /// Check that this contribution is linked to some specific parent elements.
    #[must_use]
    pub fn is_linked_to(&self, parent: &Phase2CeremonyCRS) -> bool {
        self.0.iter().zip(parent.0.iter()).all(|(x, y)| x.is_linked_to(y))
    }

    pub fn make(old: &Phase2CeremonyCRS) -> Self {
        let data = [
            &old.0[0], &old.0[1], &old.0[2], &old.0[3], &old.0[4], &old.0[5], &old.0[6],
        ];
        Self(transform_parallel(data, |old_i| {
            Phase2Contribution::make(&mut OsRng, ContributionHash::dummy(), &old_i)
        }))
    }
}

// TODO: Make the phase 1 and phase 2 functionality generic

/// Holds all of the CRS elements for phase1 in one struct, before validation.
#[derive(Clone, Debug)]
pub struct Phase1RawCeremonyCRS(pub(crate) [Phase1RawCRSElements; NUM_CIRCUITS]);

impl Phase1RawCeremonyCRS {
    /// Skip validation, performing the conversion anyways.
    ///
    /// Useful when parsing known good data.
    pub fn assume_valid(self) -> Phase1CeremonyCRS {
        match self.0 {
            [x0, x1, x2, x3, x4, x5, x6] => Phase1CeremonyCRS([
                x0.assume_valid(),
                x1.assume_valid(),
                x2.assume_valid(),
                x3.assume_valid(),
                x4.assume_valid(),
                x5.assume_valid(),
                x6.assume_valid(),
            ]),
        }
    }

    pub fn validate(self) -> Option<Phase1CeremonyCRS> {
        let out = transform_parallel(self.0, |x| x.validate().ok_or(anyhow!("failed to validate")));
        Some(Phase1CeremonyCRS(flatten_results(out).ok()?))
    }

    /// This should only be used when the data is known to be from a trusted source.
    pub fn unchecked_from_protobuf(value: pb::CeremonyCrs) -> anyhow::Result<Self> {
        Ok(Self([
            from_bytes_unchecked::<Phase1RawCRSElements>(value.spend.as_slice())?,
            from_bytes_unchecked::<Phase1RawCRSElements>(value.output.as_slice())?,
            from_bytes_unchecked::<Phase1RawCRSElements>(value.delegator_vote.as_slice())?,
            from_bytes_unchecked::<Phase1RawCRSElements>(value.undelegate_claim.as_slice())?,
            from_bytes_unchecked::<Phase1RawCRSElements>(value.swap.as_slice())?,
            from_bytes_unchecked::<Phase1RawCRSElements>(value.swap_claim.as_slice())?,
            from_bytes_unchecked::<Phase1RawCRSElements>(value.nullifer_derivation_crs.as_slice())?,
        ]))
    }
}

impl TryInto<pb::CeremonyCrs> for Phase1RawCeremonyCRS {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<pb::CeremonyCrs> {
        Ok(pb::CeremonyCrs {
            spend: to_bytes(&self.0[0])?,
            output: to_bytes(&self.0[1])?,
            delegator_vote: to_bytes(&self.0[2])?,
            undelegate_claim: to_bytes(&self.0[3])?,
            swap: to_bytes(&self.0[4])?,
            swap_claim: to_bytes(&self.0[5])?,
            nullifer_derivation_crs: to_bytes(&self.0[6])?,
        })
    }
}

impl TryFrom<pb::CeremonyCrs> for Phase1RawCeremonyCRS {
    type Error = anyhow::Error;

    fn try_from(value: pb::CeremonyCrs) -> std::result::Result<Self, Self::Error> {
        Ok(Self([
            from_bytes::<Phase1RawCRSElements>(value.spend.as_slice())?,
            from_bytes::<Phase1RawCRSElements>(value.output.as_slice())?,
            from_bytes::<Phase1RawCRSElements>(value.delegator_vote.as_slice())?,
            from_bytes::<Phase1RawCRSElements>(value.undelegate_claim.as_slice())?,
            from_bytes::<Phase1RawCRSElements>(value.swap.as_slice())?,
            from_bytes::<Phase1RawCRSElements>(value.swap_claim.as_slice())?,
            from_bytes::<Phase1RawCRSElements>(value.nullifer_derivation_crs.as_slice())?,
        ]))
    }
}

/// Holds all of the CRS elements for phase1 in one struct.
#[derive(Clone, Debug, PartialEq)]
pub struct Phase1CeremonyCRS(pub [Phase1CRSElements; NUM_CIRCUITS]);

impl From<Phase1CeremonyCRS> for Phase1RawCeremonyCRS {
    fn from(value: Phase1CeremonyCRS) -> Self {
        Self(array::from_fn(|i| value.0[i].raw.clone()))
    }
}

impl TryFrom<Phase1CeremonyCRS> for pb::CeremonyCrs {
    type Error = anyhow::Error;

    fn try_from(data: Phase1CeremonyCRS) -> Result<pb::CeremonyCrs> {
        Phase1RawCeremonyCRS::from(data).try_into()
    }
}

/// All phase1 contributions, before they've been validated.
#[derive(Clone, Debug)]
pub struct Phase1RawCeremonyContribution([Phase1RawContribution; NUM_CIRCUITS]);

impl TryInto<pb::participate_request::Contribution> for Phase1RawCeremonyContribution {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<pb::participate_request::Contribution> {
        Ok(pb::participate_request::Contribution {
            updated: Some(pb::CeremonyCrs {
                spend: to_bytes(&self.0[0].new_elements)?,
                output: to_bytes(&self.0[1].new_elements)?,
                delegator_vote: to_bytes(&self.0[2].new_elements)?,
                undelegate_claim: to_bytes(&self.0[3].new_elements)?,
                swap: to_bytes(&self.0[4].new_elements)?,
                swap_claim: to_bytes(&self.0[5].new_elements)?,
                nullifer_derivation_crs: to_bytes(&self.0[6].new_elements)?,
            }),
            update_proofs: Some(pb::CeremonyLinkingProof {
                spend: to_bytes(&self.0[0].linking_proof)?,
                output: to_bytes(&self.0[1].linking_proof)?,
                delegator_vote: to_bytes(&self.0[2].linking_proof)?,
                undelegate_claim: to_bytes(&self.0[3].linking_proof)?,
                swap: to_bytes(&self.0[4].linking_proof)?,
                swap_claim: to_bytes(&self.0[5].linking_proof)?,
                nullifer_derivation_crs: to_bytes(&self.0[6].linking_proof)?,
            }),
            parent_hashes: Some(pb::CeremonyParentHashes {
                spend: self.0[0].parent.0.to_vec(),
                output: self.0[1].parent.0.to_vec(),
                delegator_vote: self.0[2].parent.0.to_vec(),
                undelegate_claim: self.0[3].parent.0.to_vec(),
                swap: self.0[4].parent.0.to_vec(),
                swap_claim: self.0[5].parent.0.to_vec(),
                nullifer_derivation_crs: self.0[6].parent.0.to_vec(),
            }),
        })
    }
}

impl TryFrom<pb::participate_request::Contribution> for Phase1RawCeremonyContribution {
    type Error = anyhow::Error;

    fn try_from(value: pb::participate_request::Contribution) -> Result<Self> {
        let (parent_hashes, updated, update_proofs) = match value {
            pb::participate_request::Contribution {
                parent_hashes: Some(x0),
                updated: Some(x1),
                update_proofs: Some(x2),
            } => (x0, x1, x2),
            _ => anyhow::bail!("missing contribution data"),
        };
        let data = [
            (parent_hashes.spend, updated.spend, update_proofs.spend),
            (parent_hashes.output, updated.output, update_proofs.output),
            (
                parent_hashes.delegator_vote,
                updated.delegator_vote,
                update_proofs.delegator_vote,
            ),
            (
                parent_hashes.undelegate_claim,
                updated.undelegate_claim,
                update_proofs.undelegate_claim,
            ),
            (parent_hashes.swap, updated.swap, update_proofs.swap),
            (parent_hashes.swap_claim, updated.swap_claim, update_proofs.swap_claim),
            (
                parent_hashes.nullifer_derivation_crs,
                updated.nullifer_derivation_crs,
                update_proofs.nullifer_derivation_crs,
            ),
        ];
        let out = transform_parallel(data, |(parent_hash, updated, update_proof)| {
            Ok::<_, anyhow::Error>(Phase1RawContribution {
                parent: ContributionHash::try_from(parent_hash.as_slice())?,
                new_elements: from_bytes::<Phase1RawCRSElements>(updated.as_slice())?,
                linking_proof: from_bytes::<LinkingProof>(update_proof.as_slice())?,
            })
        });
        Ok(Self(flatten_results(out)?))
    }
}

impl Phase1RawCeremonyContribution {
    /// Validate that this contribution is internally consistent.
    ///
    /// This doesn't check that it's connected to the right parent though, which is an additional
    /// step you want to do.
    pub fn validate(self) -> Option<Phase1CeremonyContribution> {
        let out = transform_parallel(self.0, |x| x.validate().ok_or(anyhow!("failed to validate")));
        Some(Phase1CeremonyContribution(flatten_results(out).ok()?))
    }

    /// Skip validation, performing the conversion anyways.
    ///
    /// Useful when parsing known good data.
    pub fn assume_valid(self) -> Phase1CeremonyContribution {
        // This avoids a copy, and will break if we change the size:
        match self.0 {
            [x0, x1, x2, x3, x4, x5, x6] => Phase1CeremonyContribution([
                x0.assume_valid(),
                x1.assume_valid(),
                x2.assume_valid(),
                x3.assume_valid(),
                x4.assume_valid(),
                x5.assume_valid(),
                x6.assume_valid(),
            ]),
        }
    }

    pub fn unchecked_from_protobuf(value: pb::participate_request::Contribution) -> Result<Self> {
        let (parent_hashes, updated, update_proofs) = match value {
            pb::participate_request::Contribution {
                parent_hashes: Some(x0),
                updated: Some(x1),
                update_proofs: Some(x2),
            } => (x0, x1, x2),
            _ => anyhow::bail!("missing contribution data"),
        };
        let data = [
            (parent_hashes.spend, updated.spend, update_proofs.spend),
            (parent_hashes.output, updated.output, update_proofs.output),
            (
                parent_hashes.delegator_vote,
                updated.delegator_vote,
                update_proofs.delegator_vote,
            ),
            (
                parent_hashes.undelegate_claim,
                updated.undelegate_claim,
                update_proofs.undelegate_claim,
            ),
            (parent_hashes.swap, updated.swap, update_proofs.swap),
            (parent_hashes.swap_claim, updated.swap_claim, update_proofs.swap_claim),
            (
                parent_hashes.nullifer_derivation_crs,
                updated.nullifer_derivation_crs,
                update_proofs.nullifer_derivation_crs,
            ),
        ];
        let out = transform(data, |(parent_hash, updated, update_proof)| {
            Ok::<_, anyhow::Error>(Phase1RawContribution {
                parent: ContributionHash::try_from(parent_hash.as_slice())?,
                new_elements: from_bytes_unchecked::<Phase1RawCRSElements>(updated.as_slice())?,
                linking_proof: from_bytes_unchecked::<LinkingProof>(update_proof.as_slice())?,
            })
        });
        Ok(Self(flatten_results(out)?))
    }
}

/// Holds all of the phase1 contributions in a single package.
#[derive(Clone, Debug)]
pub struct Phase1CeremonyContribution([Phase1Contribution; NUM_CIRCUITS]);

impl From<Phase1CeremonyContribution> for Phase1RawCeremonyContribution {
    fn from(value: Phase1CeremonyContribution) -> Self {
        let out: [Phase1RawContribution; NUM_CIRCUITS] =
            array::from_fn(|i| Phase1RawContribution::from(value.0[i].clone()));
        Self(out)
    }
}

impl TryFrom<Phase1CeremonyContribution> for pb::participate_request::Contribution {
    type Error = anyhow::Error;

    fn try_from(data: Phase1CeremonyContribution) -> Result<pb::participate_request::Contribution> {
        Phase1RawCeremonyContribution::from(data).try_into()
    }
}

impl Phase1CeremonyContribution {
    /// Get the new elements contained in this contribution
    pub fn new_elements(&self) -> Phase1CeremonyCRS {
        Phase1CeremonyCRS(array::from_fn(|i| self.0[i].new_elements.clone()))
    }

    /// Check that this contribution is linked to some specific parent elements.
    #[must_use]
    pub fn is_linked_to(&self, parent: &Phase1CeremonyCRS) -> bool {
        self.0.iter().zip(parent.0.iter()).all(|(x, y)| x.is_linked_to(y))
    }

    pub fn make(old: &Phase1CeremonyCRS) -> Self {
        let data = [
            &old.0[0], &old.0[1], &old.0[2], &old.0[3], &old.0[4], &old.0[5], &old.0[6],
        ];
        Self(transform_parallel(data, |old_i| {
            Phase1Contribution::make(&mut OsRng, ContributionHash::dummy(), &old_i)
        }))
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct AllExtraTransitionInformation([ExtraTransitionInformation; NUM_CIRCUITS]);

impl AllExtraTransitionInformation {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        to_bytes(self)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Ok(from_bytes_unchecked::<Self>(data)?)
    }
}
