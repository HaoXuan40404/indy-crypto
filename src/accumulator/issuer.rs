use bn::BigNumber;
use accumulator::*;
use errors::IndyCryptoError;
use pair::*;
use accumulator::constants::*;
use accumulator::helpers::*;
use accumulator::commitment::get_pedersen_commitment;
use accumulator::hash::get_hash_as_int;

use std::collections::{HashMap, HashSet};

/// Trust source that provides credentials to prover.
pub struct Issuer {}

impl Issuer {
    pub fn new_revocation_keys() -> Result<(CredentialRevocationPublicKey,
                                            CredentialRevocationPrivateKey), IndyCryptoError> {
        trace!("Issuer::_new_credential_revocation_keys: >>>");

        let h = PointG1::new()?;
        let h0 = PointG1::new()?;
        let h1 = PointG1::new()?;
        let h2 = PointG1::new()?;
        let htilde = PointG1::new()?;
        let g = PointG1::new()?;

        let u = PointG2::new()?;
        let h_cap = PointG2::new()?;

        let x = GroupOrderElement::new()?;
        let sk = GroupOrderElement::new()?;
        let g_dash = PointG2::new()?;

        let pk = g.mul(&sk)?;
        let y = h_cap.mul(&x)?;

        let cred_rev_pub_key = CredentialRevocationPublicKey { g, g_dash, h, h0, h1, h2, htilde, h_cap, u, pk, y };
        let cred_rev_priv_key = CredentialRevocationPrivateKey { x, sk };

        trace!("Issuer::_new_credential_revocation_keys: <<< cred_rev_pub_key: {:?}, cred_rev_priv_key: {:?}", cred_rev_pub_key, secret!(&cred_rev_priv_key));

        Ok((cred_rev_pub_key, cred_rev_priv_key))
    }

    pub fn new_accumulator(cred_rev_pub_key: &CredentialRevocationPublicKey,
                           element_num: u32) -> Result<(AccumulatorPublic, AccumulatorPrivateKey), IndyCryptoError> {
        trace!("Issuer::_new_revocation_registry_keys: >>> cred_rev_pub_key: {:?}, element_num: {:?}",
               cred_rev_pub_key, element_num);
        let gamma = GroupOrderElement::new()?;

        let mut z = Pair::pair(&cred_rev_pub_key.g, &cred_rev_pub_key.g_dash)?;
        let mut pow = GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(element_num + 1))?;
        pow = gamma.pow_mod(&pow)?;
        z = z.pow(&pow)?;

        let accum = Accumulator::new_inf()?;

        let rev_key_pub = AccumulatorPublicKey { z };
        let rev_key_priv = AccumulatorPrivateKey { gamma };

        trace!("Issuer::_new_revocation_registry_keys: <<< rev_key_pub: {:?}, rev_key_priv: {:?}", rev_key_pub, secret!(&rev_key_priv));
        let accumulator_pub = AccumulatorPublic { accu_pub_key: rev_key_pub, accumulator: accum };

        Ok((accumulator_pub, rev_key_priv))
    }


    // In the anoncreds whitepaper, `credential context` is denoted by `m2`
    pub fn gen_credential_context(prover_id: &str, rev_idx: Option<u32>) -> Result<BigNumber, IndyCryptoError> {
        trace!("Issuer::_calc_m2: >>> prover_id: {:?}, rev_idx: {:?}", prover_id, secret!(rev_idx));
        let rev_idx = rev_idx.map(|i| i as i32).unwrap_or(-1);
        let prover_id_bn = encode_attribute(prover_id, ByteOrder::Little)?;
        let rev_idx_bn = encode_attribute(&rev_idx.to_string(), ByteOrder::Little)?;

        let mut values: Vec<u8> = Vec::new();
        values.extend_from_slice(&prover_id_bn.to_bytes()?);
        values.extend_from_slice(&rev_idx_bn.to_bytes()?);

        let credential_context = get_hash_as_int(&vec![values])?;

        trace!("Issuer::_gen_credential_context: <<< credential_context: {:?}", secret!(&credential_context));

        Ok(credential_context)
    }


    pub fn get_index(max_cred_num: u32, rev_idx: u32) -> u32 {
        max_cred_num + 1 - rev_idx
    }

    pub fn delete_from_accumulaor(rev_idx: u32,
                                  max_element_num: u32,
                                  accumulator_public: &mut AccumulatorPublic,
                                  rev_tails_accessor: &RevocationTailsAccessor, )
                                  -> Result<Option<RevocationRegistryDelta>, IndyCryptoError> {
        let index = Issuer::get_index(max_element_num, rev_idx);

        let rev_reg_delta =
            {
                let prev_acc = accumulator_public.accumulator.clone();
                rev_tails_accessor.access_tail(index, &mut |tail| {
                    accumulator_public.accumulator = accumulator_public.accumulator.sub(tail).unwrap();
                })?;

                Some(RevocationRegistryDelta {
                    prev_accum: Some(prev_acc),
                    accum: accumulator_public.accumulator.clone(),
                    issued: HashSet::new(),
                    revoked: hashset![rev_idx],
                })
            };

        Ok(rev_reg_delta)
    }

    pub fn add_to_accumulaor(rev_idx: u32,
                             m2: &BigNumber,
                             max_element_num: u32,
                             blinded_revocation_secrets: &BlindedRevocationSecrets,
                             accumulator_public: &mut AccumulatorPublic,
                             accumulator_private_key: &AccumulatorPrivateKey,
                             credential_revocation_public_key: &CredentialRevocationPublicKey,
                             credential_revocation_private_key: &CredentialRevocationPrivateKey,
                             rev_tails_accessor: &RevocationTailsAccessor, )
                             -> Result<(NonRevocationCredentialSignature, Option<RevocationRegistryDelta>), IndyCryptoError> {
        let s_prime_prime = GroupOrderElement::new()?;
        let c = GroupOrderElement::new()?;
        let m2 = GroupOrderElement::from_bytes(&m2.to_bytes()?)?;

        let g_i = {
            let i_bytes = transform_u32_to_array_of_u8(rev_idx);
            let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
            pow = accumulator_private_key.gamma.pow_mod(&pow)?;
            credential_revocation_public_key.g.mul(&pow)?
        };

        let ur = blinded_revocation_secrets.ur;

        let sigma =
            credential_revocation_public_key.h0.add(&credential_revocation_public_key.h1.mul(&m2)?)?
                .add(&ur)?
                .add(&g_i)?
                .add(&credential_revocation_public_key.h2.mul(&s_prime_prime)?)?
                .mul(&credential_revocation_private_key.x.add_mod(&c)?.inverse()?)?;


        let sigma_i = credential_revocation_public_key.g_dash
            .mul(&credential_revocation_private_key.sk
                .add_mod(&accumulator_private_key.gamma
                    .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(rev_idx))?)?)?
                .inverse()?)?;
        let u_i = credential_revocation_public_key.u
            .mul(&accumulator_private_key.gamma
                .pow_mod(&GroupOrderElement::from_bytes(&transform_u32_to_array_of_u8(rev_idx))?)?)?;

        let index = Issuer::get_index(max_element_num, rev_idx);

        let rev_reg_delta = {
            let prev_acc = accumulator_public.accumulator.clone();
            rev_tails_accessor.access_tail(index, &mut |tail| {
                accumulator_public.accumulator = accumulator_public.accumulator.add(tail).unwrap();
            })?;

            Some(RevocationRegistryDelta {
                prev_accum: Some(prev_acc),
                accum: accumulator_public.accumulator.clone(),
                issued: hashset![rev_idx],
                revoked: HashSet::new(),
            })
        };

        let witness_signature = WitnessSignature {
            sigma_i,
            u_i,
            g_i: g_i.clone(),
        };

        let non_revocation_cred_sig = NonRevocationCredentialSignature {
            sigma,
            c,
            s_prime_prime,
            witness_signature,
            g_i: g_i.clone(),
            i: rev_idx,
            m2,
        };

        Ok((non_revocation_cred_sig, rev_reg_delta))
    }
}