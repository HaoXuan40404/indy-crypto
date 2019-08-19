use bn::BigNumber;
use accumulator::*;
use accumulator::constants::{LARGE_E_START_VALUE, ITERATION};
use accumulator::helpers::*;
use accumulator::hash::get_hash_as_int;
use errors::IndyCryptoError;

use std::collections::BTreeSet;
use std::iter::FromIterator;

/// Party that wants to check that prover has some credentials provided by issuer.
pub struct Verifier {}

impl Verifier {
    pub fn verify(challenge: BigNumber,
                  credential_revocation_public_key: &CredentialRevocationPublicKey,
                  accumulator_pub: &AccumulatorPublic,
                  non_revoc_proof: &NonRevocProof,
                  proof_request_nonce: &BigNumber,
    ) -> Result<bool, IndyCryptoError> {
        let tau_list = Verifier::calculate_tau_list(&challenge, &credential_revocation_public_key,
                                                    &accumulator_pub, &non_revoc_proof).unwrap().as_slice().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&tau_list);
        values.extend_from_slice(&non_revoc_proof.as_c_list().unwrap());
        values.push(proof_request_nonce.to_bytes().unwrap());

        let c_hver = get_hash_as_int(&values).unwrap();
        let valid = c_hver == challenge;
        trace!("ProofVerifier::verify: <<< valid: {:?}", valid);
        Ok(valid)
    }


    pub fn calculate_tau_list(challenge: &BigNumber,
                              r_pub_key: &CredentialRevocationPublicKey,
                              accumulator_public: &AccumulatorPublic,
                              proof: &NonRevocProof) -> Result<NonRevocProofTauList, IndyCryptoError> {
        trace!("ProofVerifier::_verify_non_revocation_proof: >>> r_pub_key: {:?}, accumulator_public: {:?},  challenge: {:?}",
               r_pub_key, accumulator_public, challenge);

        let ch_num_z = bignum_to_group_element(&challenge)?;

        let t_hat_expected_values = create_tau_list_expected_val(r_pub_key, accumulator_public, &proof.c_list)?;
        let t_hat_calc_values =
            create_tau_list_values2(&r_pub_key, accumulator_public, &proof.x_list, &proof.c_list)?;

        let non_revoc_proof_tau_list = NonRevocProofTauList {
            t1: t_hat_expected_values.t1.mul(&ch_num_z)?.add(&t_hat_calc_values.t1)?,
            t2: t_hat_expected_values.t2.mul(&ch_num_z)?.add(&t_hat_calc_values.t2)?,
            t3: t_hat_expected_values.t3.pow(&ch_num_z)?.mul(&t_hat_calc_values.t3)?,
            t4: t_hat_expected_values.t4.pow(&ch_num_z)?.mul(&t_hat_calc_values.t4)?,
            t5: t_hat_expected_values.t5.mul(&ch_num_z)?.add(&t_hat_calc_values.t5)?,
            t6: t_hat_expected_values.t6.mul(&ch_num_z)?.add(&t_hat_calc_values.t6)?,
            t7: t_hat_expected_values.t7.pow(&ch_num_z)?.mul(&t_hat_calc_values.t7)?,
            t8: t_hat_expected_values.t8.pow(&ch_num_z)?.mul(&t_hat_calc_values.t8)?,
        };

        trace!("ProofVerifier::_verify_non_revocation_proof: <<< non_revoc_proof_tau_list: {:?}", non_revoc_proof_tau_list);
        Ok(non_revoc_proof_tau_list)
    }
}