//! This library contains the backend logic for running a zero
//! knowledge proof system setup ceremony, designed to generate a
//! genesis block out of the contributions from many people. The
//! theory is that the more contributors that participate from the
//! general public, the less likely it is that every contributor is
//! dishonest. It only takes one honest contributor to create a secure
//! genesis block. This ceremony is different to previously run setup
//! ceremonies in that it allows multiple contributors to contribute
//! in parallel.
//!
//! The central piece of code of this library is the [Coordinator],
//! which orchestrates the ceremony. The coordinator is created with a
//! set of parameters specified in [environment::Environment], these
//! parameters will differ between development, testing and production
//! use cases.
//!
//! A ceremony consists of 3 different types of
//! [objects::Participant]s. Regular contributors, replacement
//! contributors (which wait in standby during a round to replace a
//! contributor which is dropped), and verifiers which verify the
//! submitted contributions as they arrive.
//!
//! See [objects::task::initialize_tasks] for an in depth explanation
//! of how the [objects::task::Task]s for each participant in the
//! ceremony are generated depending on the number of chunks and the
//! number of participants in the round.

#[macro_use]
mod macros;

pub mod authentication;

pub(crate) mod commands;

pub mod coordinator;
pub use coordinator::*;

#[cfg(not(feature = "operator"))]
pub(crate) mod coordinator_state;
#[cfg(not(feature = "operator"))]
pub(crate) use coordinator_state::CoordinatorState;

#[cfg(feature = "operator")]
pub mod coordinator_state;
#[cfg(feature = "operator")]
pub use coordinator_state::CoordinatorState;

pub mod environment;

pub mod objects;
pub use objects::{ContributionFileSignature, ContributionState, Participant, Round};

pub mod storage;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
pub mod tests;

pub mod penumbra;
pub mod shim;
