use bn::BigNumber;
use accumulator::*;
use accumulator::constants::*;
use errors::IndyCryptoError;
use pair::*;
use super::helpers::*;
use accumulator::commitment::get_pedersen_commitment;
use accumulator::hash::get_hash_as_int;

use std::collections::{HashSet, BTreeMap, BTreeSet};

use std::iter::FromIterator;

/// Credentials owner that can proof and partially disclose the credentials to verifier.
pub struct Prover {}

impl Prover {
    pub fn generate_blinded_revocation(credential_revocation_public_key: &CredentialRevocationPublicKey) -> Result<BlindedRevocationSecrets, IndyCryptoError> {
        trace!("Prover::_generate_blinded_revocation_credential_secrets: >>> r_pub_key: {:?}", credential_revocation_public_key);
        let s_prime = GroupOrderElement::new()?;
        let ur = credential_revocation_public_key.h2.mul(&s_prime)?;
        let blinded_revocation_secrets = BlindedRevocationSecrets { ur, s_prime };
        trace!("Prover::_generate_blinded_revocation_credential_secrets: <<< revocation_blinded_credential_secrets: {:?}", blinded_revocation_secrets);
        Ok(blinded_revocation_secrets)
    }

    //检验撤销凭证是否正确
    pub fn check_revocation_credential(r_cred: &mut NonRevocationCredentialSignature,
                                       blinded_revocation_secrets: &BlindedRevocationSecrets,
                                       credential_revocation_pub_key: &CredentialRevocationPublicKey,
                                       accumulator_public: &AccumulatorPublic,
                                       witness: &Witness) -> Result<(), IndyCryptoError> {
        let s_prime: GroupOrderElement = blinded_revocation_secrets.s_prime;

        trace!("Prover::_process_non_revocation_credential: >>> r_cred: {:?}, vr_prime: {:?}, credential_revocation_pub_key: {:?},  rev_key_pub: {:?}",
               r_cred, s_prime, credential_revocation_pub_key, accumulator_public);

        let r_cnxt_m2 = BigNumber::from_bytes(&r_cred.m2.to_bytes()?)?;
        // 下面这步做偏移
        let s = s_prime.add_mod(&r_cred.s_prime_prime)?;

        let z_calc = Pair::pair(&r_cred.witness_signature.g_i, &accumulator_public.accumulator)?
            .mul(&Pair::pair(&credential_revocation_pub_key.g, &witness.omega)?.inverse()?)?;
        if z_calc != accumulator_public.accu_pub_key.z {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        let pair_gg_calc = Pair::pair(&credential_revocation_pub_key.pk.add(&r_cred.g_i)?, &r_cred.witness_signature.sigma_i)?;
        let pair_gg = Pair::pair(&credential_revocation_pub_key.g, &credential_revocation_pub_key.g_dash)?;
        if pair_gg_calc != pair_gg {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        let m2 = GroupOrderElement::from_bytes(&r_cnxt_m2.to_bytes()?)?;

        let pair_h1 = Pair::pair(&r_cred.sigma, &credential_revocation_pub_key.y.add(&credential_revocation_pub_key.h_cap.mul(&r_cred.c)?)?)?;
        let pair_h2 = Pair::pair(
            &credential_revocation_pub_key.h0
                .add(&credential_revocation_pub_key.h1.mul(&m2)?)?
                .add(&credential_revocation_pub_key.h2.mul(&s)?)?
                .add(&r_cred.g_i)?,
            &credential_revocation_pub_key.h_cap,
        )?;
        if pair_h1 != pair_h2 {
            return Err(IndyCryptoError::InvalidStructure("Issuer is sending incorrect data".to_string()));
        }

        trace!("Prover::_process_non_revocation_credential: <<<");

        Ok(())
    }

    pub fn store_non_revocation_credential(non_revocation_credential_signature: &mut NonRevocationCredentialSignature,
                                           blinded_revocation_secrets: &BlindedRevocationSecrets) -> Result<(), IndyCryptoError> {
        let ref s_prime = blinded_revocation_secrets.s_prime;
        non_revocation_credential_signature.s_prime_prime = s_prime.add_mod(&non_revocation_credential_signature.s_prime_prime)?;
        Ok(())
    }

    pub fn init_non_revocation_proof(r_cred: &NonRevocationCredentialSignature,
                                     accumulator_public: &AccumulatorPublic,
                                     cred_rev_pub_key: &CredentialRevocationPublicKey,
                                     witness: &Witness) -> Result<NonRevocInitProof, IndyCryptoError> {
        let c_list_params = ProofBuilder::_gen_c_list_params(&r_cred)?;
        let c_list = ProofBuilder::_create_c_list_values(&r_cred, &c_list_params, &cred_rev_pub_key, witness)?;
        let tau_list_params = ProofBuilder::_gen_tau_list_params()?;
        let tau_list = get_tau_list(&cred_rev_pub_key,
                                    &accumulator_public,
                                    &tau_list_params,
                                    &c_list)?;
        let r_init_proof = NonRevocInitProof {
            c_list_params,
            tau_list_params,
            c_list,
            tau_list,
        };

        trace!("ProofBuilder::_init_non_revocation_proof: <<< r_init_proof: {:?}", r_init_proof);

        Ok(r_init_proof)
    }


    pub fn finalize_non_revocation_proof(init_proof: &NonRevocInitProof, c_h: &BigNumber) -> Result<NonRevocProof, IndyCryptoError> {
        trace!("ProofBuilder::_finalize_non_revocation_proof: >>> init_proof: {:?}, c_h: {:?}", init_proof, c_h);

        let ch_num_z = bignum_to_group_element(&c_h)?;
        let mut x_list: Vec<GroupOrderElement> = Vec::new();

        for (x, y) in init_proof.tau_list_params.as_list()?.iter().zip(init_proof.c_list_params.as_list()?.iter()) {
            x_list.push(x.add_mod(
                &ch_num_z.mul_mod(&y)?.mod_neg()?
            )?);
        }

        let non_revoc_proof = NonRevocProof {
            x_list: NonRevocProofXList::from_list(x_list),
            c_list: init_proof.c_list.clone(),
        };

        trace!("ProofBuilder::_finalize_non_revocation_proof: <<< non_revoc_proof: {:?}", non_revoc_proof);

        Ok(non_revoc_proof)
    }
}

#[derive(Debug)]
pub struct ProofBuilder {
    common_attributes: HashMap<String, BigNumber>,
    c_list: Vec<Vec<u8>>,
    tau_list: Vec<Vec<u8>>,
}

impl ProofBuilder {
    fn _gen_c_list_params(r_cred: &NonRevocationCredentialSignature) -> Result<NonRevocProofXList, IndyCryptoError> {
        trace!("ProofBuilder::_gen_c_list_params: >>> r_cred: {:?}", r_cred);

        let rho = GroupOrderElement::new()?;
        let r = GroupOrderElement::new()?;
        let r_prime = GroupOrderElement::new()?;
        let r_prime_prime = GroupOrderElement::new()?;
        let r_prime_prime_prime = GroupOrderElement::new()?;
        let o = GroupOrderElement::new()?;
        let o_prime = GroupOrderElement::new()?;
        let m = rho.mul_mod(&r_cred.c)?;
        let m_prime = r.mul_mod(&r_prime_prime)?;
        let t = o.mul_mod(&r_cred.c)?;
        let t_prime = o_prime.mul_mod(&r_prime_prime)?;
        let m2 = GroupOrderElement::from_bytes(&r_cred.m2.to_bytes()?)?;

        let non_revoc_proof_x_list = NonRevocProofXList {
            rho,
            r,
            r_prime,
            r_prime_prime,
            r_prime_prime_prime,
            o,
            o_prime,
            m,
            m_prime,
            t,
            t_prime,
            m2,
            s: r_cred.s_prime_prime,
            c: r_cred.c,
        };

        trace!("ProofBuilder::_gen_c_list_params: <<< non_revoc_proof_x_list: {:?}", non_revoc_proof_x_list);

        Ok(non_revoc_proof_x_list)
    }

    fn _create_c_list_values(r_cred: &NonRevocationCredentialSignature,
                             params: &NonRevocProofXList,
                             r_pub_key: &CredentialRevocationPublicKey,
                             witness: &Witness) -> Result<NonRevocProofCList, IndyCryptoError> {
        trace!("ProofBuilder::_create_c_list_values: >>> r_cred: {:?}, r_pub_key: {:?}", r_cred, r_pub_key);

        let e = r_pub_key.h
            .mul(&params.rho)?
            .add(
                &r_pub_key.htilde.mul(&params.o)?
            )?;

        let d = r_pub_key.g
            .mul(&params.r)?
            .add(
                &r_pub_key.htilde.mul(&params.o_prime)?
            )?;

        let a = r_cred.sigma
            .add(
                &r_pub_key.htilde.mul(&params.rho)?
            )?;

        let g = r_cred.g_i
            .add(
                &r_pub_key.htilde.mul(&params.r)?
            )?;

        let w = witness.omega
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime)?
            )?;

        let s = r_cred.witness_signature.sigma_i
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime_prime)?
            )?;

        let u = r_cred.witness_signature.u_i
            .add(
                &r_pub_key.h_cap.mul(&params.r_prime_prime_prime)?
            )?;

        let non_revoc_proof_c_list = NonRevocProofCList {
            e,
            d,
            a,
            g,
            w,
            s,
            u,
        };

        trace!("ProofBuilder::_create_c_list_values: <<< non_revoc_proof_c_list: {:?}", non_revoc_proof_c_list);

        Ok(non_revoc_proof_c_list)
    }

    fn _gen_tau_list_params() -> Result<NonRevocProofXList, IndyCryptoError> {
        trace!("ProofBuilder::_gen_tau_list_params: >>>");

        let non_revoc_proof_x_list = NonRevocProofXList {
            rho: GroupOrderElement::new()?,
            r: GroupOrderElement::new()?,
            r_prime: GroupOrderElement::new()?,
            r_prime_prime: GroupOrderElement::new()?,
            r_prime_prime_prime: GroupOrderElement::new()?,
            o: GroupOrderElement::new()?,
            o_prime: GroupOrderElement::new()?,
            m: GroupOrderElement::new()?,
            m_prime: GroupOrderElement::new()?,
            t: GroupOrderElement::new()?,
            t_prime: GroupOrderElement::new()?,
            m2: GroupOrderElement::new()?,
            s: GroupOrderElement::new()?,
            c: GroupOrderElement::new()?,
        };

        trace!("ProofBuilder::_gen_tau_list_params: <<< Nnon_revoc_proof_x_list: {:?}", non_revoc_proof_x_list);

        Ok(non_revoc_proof_x_list)
    }
}