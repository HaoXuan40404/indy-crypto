#[macro_use]
pub mod logger;
mod commitment;
mod constants;
#[macro_use]
mod datastructures;
#[macro_use]
mod helpers;
mod hash;
pub mod issuer;
pub mod prover;
pub mod verifier;

use bn::BigNumber;
use errors::IndyCryptoError;
use pair::*;

use std::collections::{HashMap, HashSet, BTreeSet, BTreeMap};
use std::hash::Hash;
use accumulator::hash::get_hash_as_int;

use colored::*;
use std::io;

/// Creates random nonce
///
/// # Example
/// ```
/// use indy_crypto::accumulator::new_nonce;
///
/// let _nonce = new_nonce().unwrap();
/// ```
pub fn new_nonce() -> Result<Nonce, IndyCryptoError> {
    Ok(helpers::bn_rand(constants::LARGE_NONCE)?)
}

/// `Revocation Public Key` is used to verify that credential was'nt revoked by Issuer.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CredentialRevocationPublicKey {
    g: PointG1,
    g_dash: PointG2,
    h: PointG1,
    h0: PointG1,
    h1: PointG1,
    h2: PointG1,
    htilde: PointG1,
    h_cap: PointG2,
    u: PointG2,
    pk: PointG1,
    y: PointG2,
}

/// `Revocation Private Key` is used for signing Credential.
#[derive(Debug, Deserialize, Serialize)]
pub struct CredentialRevocationPrivateKey {
    x: GroupOrderElement,
    sk: GroupOrderElement,
}

pub type Accumulator = PointG2;


/// `Revocation Registry Delta` contains Accumulator changes.
/// Must be applied to `Revocation Registry`
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    prev_accum: Option<Accumulator>,
    accum: Accumulator,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    issued: HashSet<u32>,
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    #[serde(default)]
    revoked: HashSet<u32>,
}

impl RevocationRegistryDelta {
    pub fn merge(&mut self, other_delta: &RevocationRegistryDelta) -> Result<(), IndyCryptoError> {
        if other_delta.prev_accum.is_none() || self.accum != other_delta.prev_accum.unwrap() {
            return Err(IndyCryptoError::InvalidStructure(format!("Deltas can not be merged.")));
        }

        self.accum = other_delta.accum;

        self.issued.extend(
            other_delta.issued.difference(&self.revoked));

        self.revoked.extend(
            other_delta.revoked.difference(&self.issued));

        for index in other_delta.revoked.iter() {
            self.issued.remove(index);
        }

        for index in other_delta.issued.iter() {
            self.revoked.remove(index);
        }

        Ok(())
    }
}


/// `Revocation Key Public` Accumulator public key.
/// Must be published together with Accumulator
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccumulatorPublicKey {
    z: Pair
}

/// `Revocation Key Private` Accumulator primate key.
#[derive(Debug, Deserialize, Serialize)]
pub struct AccumulatorPrivateKey {
    gamma: GroupOrderElement
}

/// `Revocation Key Private` Accumulator primate key.
#[derive(Debug, Deserialize, Serialize)]
pub struct AccumulatorPublic {
    accu_pub_key: AccumulatorPublicKey,
    accumulator: PointG2,
}


/// `Tail` point of curve used to update accumulator.
pub type Tail = PointG2;

impl Tail {
    fn new_tail(index: u32, g_dash: &PointG2, gamma: &GroupOrderElement) -> Result<Tail, IndyCryptoError> {
        let i_bytes = helpers::transform_u32_to_array_of_u8(index);
        let mut pow = GroupOrderElement::from_bytes(&i_bytes)?;
        pow = gamma.pow_mod(&pow)?;
        Ok(g_dash.mul(&pow)?)
    }
}

/// Generator of `Tail's`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevocationTailsGenerator {
    size: u32,
    current_index: u32,
    g_dash: PointG2,
    gamma: GroupOrderElement,
}

impl RevocationTailsGenerator {
    fn new(max_cred_num: u32, gamma: GroupOrderElement, g_dash: PointG2) -> Self {
        RevocationTailsGenerator {
            size: 2 * max_cred_num + 1,
            /* Unused 0th + valuable 1..L + unused (L+1)th + valuable (L+2)..(2L) */
            current_index: 0,
            gamma,
            g_dash,
        }
    }

    pub fn count(&self) -> u32 {
        self.size - self.current_index
    }

    pub fn next(&mut self) -> Result<Option<Tail>, IndyCryptoError> {
        if self.current_index >= self.size {
            return Ok(None);
        }

        let tail = Tail::new_tail(self.current_index, &self.g_dash, &self.gamma)?;

        self.current_index += 1;

        Ok(Some(tail))
    }
}

pub trait RevocationTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut FnMut(&Tail)) -> Result<(), IndyCryptoError>;
}

/// Simple implementation of `RevocationTailsAccessor` that stores all tails as BTreeMap.
#[derive(Debug, Clone)]
pub struct SimpleTailsAccessor {
    tails: Vec<Tail>
}

impl RevocationTailsAccessor for SimpleTailsAccessor {
    fn access_tail(&self, tail_id: u32, accessor: &mut FnMut(&Tail)) -> Result<(), IndyCryptoError> {
        Ok(accessor(&self.tails[tail_id as usize]))
    }
}

impl SimpleTailsAccessor {
    pub fn new(rev_tails_generator: &mut RevocationTailsGenerator) -> Result<SimpleTailsAccessor, IndyCryptoError> {
        let mut tails: Vec<Tail> = Vec::new();
        while let Some(tail) = rev_tails_generator.next()? {
            tails.push(tail);
        }
        Ok(SimpleTailsAccessor { tails })
    }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NonRevocationCredentialSignature {
    sigma: PointG1,
    c: GroupOrderElement,
    s_prime_prime: GroupOrderElement,
    witness_signature: WitnessSignature,
    g_i: PointG1,
    i: u32,
    m2: GroupOrderElement,
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Witness {
    omega: PointG2
}

impl Witness {
    pub fn new<RTA>(rev_idx: u32,
                    max_cred_num: u32,
                    rev_reg_delta: &RevocationRegistryDelta,
                    rev_tails_accessor: &RTA) -> Result<Witness, IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Witness::new: >>> rev_idx: {:?}, max_cred_num: {:?},  rev_reg_delta: {:?}",
               rev_idx, max_cred_num, rev_reg_delta);

        let mut omega = PointG2::new_inf()?;

        let mut issued = rev_reg_delta.issued.clone();

        issued.remove(&rev_idx);

        for j in issued.iter() {
            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega = omega.add(tail).unwrap();
            })?;
        }

        let witness = Witness { omega };

        trace!("Witness::new: <<< witness: {:?}", witness);

        Ok(witness)
    }

    pub fn update<RTA>(&mut self,
                       rev_idx: u32,
                       max_cred_num: u32,
                       rev_reg_delta: &RevocationRegistryDelta,
                       rev_tails_accessor: &RTA) -> Result<(), IndyCryptoError> where RTA: RevocationTailsAccessor {
        trace!("Witness::update: >>> rev_idx: {:?}, max_cred_num: {:?}, rev_reg_delta: {:?}",
               rev_idx, max_cred_num, rev_reg_delta);

        let mut omega_denom = PointG2::new_inf()?;
        for j in rev_reg_delta.revoked.iter() {
            if rev_idx.eq(j) { continue; }

            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega_denom = omega_denom.add(tail).unwrap();
            })?;
        }

        let mut omega_num = PointG2::new_inf()?;
        for j in rev_reg_delta.issued.iter() {
            if rev_idx.eq(j) { continue; }

            let index = max_cred_num + 1 - j + rev_idx;
            rev_tails_accessor.access_tail(index, &mut |tail| {
                omega_num = omega_num.add(tail).unwrap();
            })?;
        }

        let mut new_omega = PointG2::new_inf()?;
        if omega_num.eq(&new_omega) {
            if omega_denom.eq(&self.omega) {
                new_omega = PointG2::new_inf()?;
            }
        } else {
            new_omega = self.omega.add(&omega_num.sub(&omega_denom)?)?;
        }

        self.omega = new_omega;

        trace!("Witness::update: <<<");

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WitnessSignature {
    sigma_i: PointG2,
    u_i: PointG2,
    g_i: PointG1,
}

#[derive(Debug)]
pub struct BlindedRevocationSecrets {
    ur: PointG1,
    s_prime: GroupOrderElement,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct BlindedCredentialSecretsCorrectnessProof {
    c: BigNumber,
    // Fiat-Shamir challenge hash
    v_dash_cap: BigNumber,
    // Value to prove knowledge of `u` construction in `BlindedCredentialSecrets`
    m_caps: BTreeMap<String, BigNumber>,
    // Values for proving knowledge of committed values
    r_caps: BTreeMap<String, BigNumber>, // Blinding values for m_caps
}

/// “Sub Proof Request” - input to create a Proof for a credential;
/// Contains attributes to be revealed and predicates.
#[derive(Debug, Clone)]
pub struct SubProofRequest {
    revealed_attrs: BTreeSet<String>,
    predicates: BTreeSet<Predicate>,
}

/// Builder of “Sub Proof Request”.
#[derive(Debug)]
pub struct SubProofRequestBuilder {
    value: SubProofRequest
}

impl SubProofRequestBuilder {
    pub fn new() -> Result<SubProofRequestBuilder, IndyCryptoError> {
        Ok(SubProofRequestBuilder {
            value: SubProofRequest {
                revealed_attrs: BTreeSet::new(),
                predicates: BTreeSet::new(),
            }
        })
    }

    pub fn add_revealed_attr(&mut self, attr: &str) -> Result<(), IndyCryptoError> {
        self.value.revealed_attrs.insert(attr.to_owned());
        Ok(())
    }

    pub fn add_predicate(&mut self, attr_name: &str, p_type: &str, value: i32) -> Result<(), IndyCryptoError> {
        let p_type = match p_type {
            "GE" => PredicateType::GE,
            "LE" => PredicateType::LE,
            "GT" => PredicateType::GT,
            "LT" => PredicateType::LT,
            p_type => return Err(IndyCryptoError::InvalidStructure(format!("Invalid predicate type: {:?}", p_type)))
        };

        let predicate = Predicate {
            attr_name: attr_name.to_owned(),
            p_type,
            value,
        };

        self.value.predicates.insert(predicate);
        Ok(())
    }

    pub fn finalize(self) -> Result<SubProofRequest, IndyCryptoError> {
        Ok(self.value)
    }
}

/// Some condition that must be satisfied.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct Predicate {
    attr_name: String,
    p_type: PredicateType,
    value: i32,
}

impl Predicate {
    pub fn get_delta(&self, attr_value: i32) -> i32 {
        match self.p_type {
            PredicateType::GE => attr_value - self.value,
            PredicateType::GT => attr_value - self.value - 1,
            PredicateType::LE => self.value - attr_value,
            PredicateType::LT => self.value - attr_value - 1
        }
    }

    pub fn get_delta_prime(&self) -> Result<BigNumber, IndyCryptoError> {
        match self.p_type {
            PredicateType::GE => BigNumber::from_dec(&self.value.to_string()),
            PredicateType::GT => BigNumber::from_dec(&(self.value + 1).to_string()),
            PredicateType::LE => BigNumber::from_dec(&self.value.to_string()),
            PredicateType::LT => BigNumber::from_dec(&(self.value - 1).to_string())
        }
    }

    pub fn is_less(&self) -> bool {
        match self.p_type {
            PredicateType::GE | PredicateType::GT => false,
            PredicateType::LE | PredicateType::LT => true
        }
    }
}

/// Condition type
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub enum PredicateType {
    GE,
    LE,
    GT,
    LT,
}

/// Proof is complex crypto structure created by prover over multiple credentials that allows to prove that prover:
/// 1) Knows signature over credentials issued with specific issuer keys (identified by key id)
/// 2) Credential contains attributes with specific values that prover wants to disclose
/// 3) Credential contains attributes with valid predicates that verifier wants the prover to satisfy.
#[derive(Debug, Deserialize, Serialize)]
pub struct Proof {
    proofs: Vec<SubProof>,
    aggregated_proof: AggregatedProof,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SubProof {
    primary_proof: PrimaryProof,
    non_revoc_proof: Option<NonRevocProof>,
}

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AggregatedProof {
    c_hash: BigNumber,
    c_list: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryProof {
    eq_proof: PrimaryEqualProof,
    ne_proofs: Vec<PrimaryPredicateInequalityProof>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct PrimaryEqualProof {
    revealed_attrs: BTreeMap<String /* attr_name of revealed */, BigNumber>,
    a_prime: BigNumber,
    e: BigNumber,
    v: BigNumber,
    m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
    m2: BigNumber,
}

impl<'a> ::serde::de::Deserialize<'a> for PrimaryEqualProof {
    fn deserialize<D: ::serde::de::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct PrimaryEqualProofV1 {
            revealed_attrs: BTreeMap<String /* attr_name of revealed */, BigNumber>,
            a_prime: BigNumber,
            e: BigNumber,
            v: BigNumber,
            m: HashMap<String /* attr_name of all except revealed */, BigNumber>,
            #[serde(default)]
            m1: BigNumber,
            m2: BigNumber,
        }

        let mut helper = PrimaryEqualProofV1::deserialize(deserializer)?;
        if helper.m1 != BigNumber::default() {
            helper.m.insert("master_secret".to_string(), helper.m1);
        }
        Ok(PrimaryEqualProof {
            revealed_attrs: helper.revealed_attrs,
            a_prime: helper.a_prime,
            e: helper.e,
            v: helper.v,
            m: helper.m,
            m2: helper.m2,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrimaryPredicateInequalityProof {
    u: HashMap<String, BigNumber>,
    r: HashMap<String, BigNumber>,
    mj: BigNumber,
    alpha: BigNumber,
    t: HashMap<String, BigNumber>,
    predicate: Predicate,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NonRevocProof {
    x_list: NonRevocProofXList,
    c_list: NonRevocProofCList,
}


impl NonRevocProof {
    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.c_list.as_list()?;
        Ok(vec)
    }
}


#[derive(Debug)]
pub struct NonRevocInitProof {
    c_list_params: NonRevocProofXList,
    tau_list_params: NonRevocProofXList,
    c_list: NonRevocProofCList,
    tau_list: NonRevocProofTauList,
}

impl NonRevocInitProof {
    pub fn as_c_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.c_list.as_list()?;
        Ok(vec)
    }

    pub fn as_tau_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        let vec = self.tau_list.as_slice()?;
        Ok(vec)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocProofXList {
    rho: GroupOrderElement,
    r: GroupOrderElement,
    r_prime: GroupOrderElement,
    r_prime_prime: GroupOrderElement,
    r_prime_prime_prime: GroupOrderElement,
    o: GroupOrderElement,
    o_prime: GroupOrderElement,
    m: GroupOrderElement,
    m_prime: GroupOrderElement,
    t: GroupOrderElement,
    t_prime: GroupOrderElement,
    m2: GroupOrderElement,
    s: GroupOrderElement,
    c: GroupOrderElement,
}

impl NonRevocProofXList {
    pub fn as_list(&self) -> Result<Vec<GroupOrderElement>, IndyCryptoError> {
        Ok(vec![
            self.rho,
            self.o,
            self.c,
            self.o_prime,
            self.m,
            self.m_prime,
            self.t,
            self.t_prime,
            self.m2,
            self.s,
            self.r,
            self.r_prime,
            self.r_prime_prime,
            self.r_prime_prime_prime,
        ])
    }

    pub fn from_list(seq: Vec<GroupOrderElement>) -> NonRevocProofXList {
        NonRevocProofXList {
            rho: seq[0],
            r: seq[10],
            r_prime: seq[11],
            r_prime_prime: seq[12],
            r_prime_prime_prime: seq[13],
            o: seq[1],
            o_prime: seq[3],
            m: seq[4],
            m_prime: seq[5],
            t: seq[6],
            t_prime: seq[7],
            m2: seq[8],
            s: seq[9],
            c: seq[2],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonRevocProofCList {
    e: PointG1,
    d: PointG1,
    a: PointG1,
    g: PointG1,
    w: PointG2,
    s: PointG2,
    u: PointG2,
}

impl NonRevocProofCList {
    pub fn as_list(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![
            self.e.to_bytes()?,
            self.d.to_bytes()?,
            self.a.to_bytes()?,
            self.g.to_bytes()?,
            self.w.to_bytes()?,
            self.s.to_bytes()?,
            self.u.to_bytes()?,
        ])
    }
}

#[derive(Clone, Debug)]
pub struct NonRevocProofTauList {
    t1: PointG1,
    t2: PointG1,
    t3: Pair,
    t4: Pair,
    t5: PointG1,
    t6: PointG1,
    t7: Pair,
    t8: Pair,
}

impl NonRevocProofTauList {
    pub fn as_slice(&self) -> Result<Vec<Vec<u8>>, IndyCryptoError> {
        Ok(vec![
            self.t1.to_bytes()?,
            self.t2.to_bytes()?,
            self.t3.to_bytes()?,
            self.t4.to_bytes()?,
            self.t5.to_bytes()?,
            self.t6.to_bytes()?,
            self.t7.to_bytes()?,
            self.t8.to_bytes()?,
        ])
    }
}

/// Random BigNumber that uses `Prover` for proof generation and `Verifier` for proof verification.
pub type Nonce = BigNumber;

trait BytesView {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError>;
}

impl BytesView for BigNumber {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for PointG1 {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for GroupOrderElement {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

impl BytesView for Pair {
    fn to_bytes(&self) -> Result<Vec<u8>, IndyCryptoError> {
        Ok(self.to_bytes()?)
    }
}

trait AppendByteArray {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError>;
}

impl AppendByteArray for Vec<Vec<u8>> {
    fn append_vec<T: BytesView>(&mut self, other: &Vec<T>) -> Result<(), IndyCryptoError> {
        for el in other.iter() {
            self.push(el.to_bytes()?);
        }
        Ok(())
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use serde_json;
    use self::issuer::Issuer;
    use self::prover::Prover;
    use self::verifier::Verifier;

    #[test]
    fn evaluateEfficiency() {

    }

    #[test]
    fn demo_10000_witness() {
        extern crate chrono;
//        use chrono::prelude::*;
        let time1 = format!("{}", chrono::Utc::now().timestamp_millis());
        println!("time: {}", time1);
        let max_element_num = 1;
        let (credential_revocation_public_key, credential_revocation_private_key) =
        Issuer::new_revocation_keys().unwrap();
        let (mut accumulator_pub, accumulator_pri_key) = Issuer::new_accumulator(&credential_revocation_public_key, max_element_num).unwrap();
        let mut rev_tails_generator = RevocationTailsGenerator::new(
            max_element_num,
            accumulator_pri_key.gamma.clone(),
            credential_revocation_public_key.g_dash.clone());
        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
        let mut non_revocation_credential_signatures = Vec::new();
        let mut revocation_registry_deltas = Vec::new();
        let mut vector_witness = Vec::new();
//        let mut blinded_revocation_secrets_vec =Vec::new();
        for i in 0..max_element_num as usize {
            let blinded_revocation_secrets = Prover::generate_blinded_revocation(&credential_revocation_public_key).unwrap();
            let prover_id = format!("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFV{:?}",i);
            let m2 = Issuer::gen_credential_context(&prover_id, Some(i as u32)).unwrap();
//            blinded_revocation_secrets_vec.push(blinded_revocation_secrets);
            let (mut non_revocation_credential_signature1, revocation_registry_delta1) =
                Issuer::add_to_accumulaor(i as u32, &m2, max_element_num, &blinded_revocation_secrets, &mut accumulator_pub,
                                          &accumulator_pri_key, &credential_revocation_public_key, &credential_revocation_private_key, &simple_tail_accessor).unwrap();
            let revocation_registry_delta1 = revocation_registry_delta1.unwrap();
            let mut witness1 = Witness::new(i as u32, max_element_num, &revocation_registry_delta1, &simple_tail_accessor).unwrap();
            Prover::check_revocation_credential(&mut non_revocation_credential_signature1,
                                                &blinded_revocation_secrets, &credential_revocation_public_key, &accumulator_pub, &witness1);
            vector_witness.push(witness1);
            Prover::store_non_revocation_credential(&mut non_revocation_credential_signature1, &blinded_revocation_secrets);
            non_revocation_credential_signatures.push(non_revocation_credential_signature1);
            revocation_registry_deltas.push(revocation_registry_delta1);
        }
        for i in 0..max_element_num as usize {
            for j in 0..max_element_num as usize {
                if i==j {
                    continue;
                }
                vector_witness[i].update(i as u32, max_element_num, &revocation_registry_deltas[j], &simple_tail_accessor).unwrap();
            }
        }
        let time2 = format!("{}", chrono::Utc::now().timestamp_millis());
        println!("time: {}", time2);

        let time1_int: i32 = time1.parse().unwrap();
        let time2_int: i32 = time2.parse().unwrap();
        println!("init time = {}ms", time2_int - time1_int);
        let non_revoc_init_proof1 = Prover::init_non_revocation_proof(&non_revocation_credential_signatures[0],
                                                                      &accumulator_pub, &credential_revocation_public_key, &vector_witness[0]).unwrap();
        let proof_request_nonce1 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof1.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof1.as_c_list().unwrap());
        values.push(proof_request_nonce1.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge1 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof1 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof1, &challenge1).unwrap();
        let time1 = format!("{}", chrono::Utc::now().timestamp_millis());

        let result = Verifier::verify(challenge1, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof1, &proof_request_nonce1).unwrap();
        assert_eq!(result, true);
        let time2 = format!("{}", chrono::Utc::now().timestamp_millis());
        let time1_int: i32 = time1.parse().unwrap();
        let time2_int: i32 = time2.parse().unwrap();
        println!("verify time = {}ms", time2_int - time1_int);

    }

    #[test]
    fn demo_time_accumulator() {
        let time_start = chrono::Utc::now().timestamp_millis();
        let max_element_num = 100;
        let (credential_revocation_public_key, credential_revocation_private_key) =
            Issuer::new_revocation_keys().unwrap();
        let (mut accumulator_pub, accumulator_pri_key) = Issuer::new_accumulator(&credential_revocation_public_key, max_element_num).unwrap();

        let mut rev_tails_generator = RevocationTailsGenerator::new(
            max_element_num,
            accumulator_pri_key.gamma.clone(),
            credential_revocation_public_key.g_dash.clone());
        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("Issuer初始化公私钥对时间{}ms", time_end - time_start);


        let time_start = chrono::Utc::now().timestamp_millis();
        let blinded_revocation_secrets = Prover::generate_blinded_revocation(&credential_revocation_public_key).unwrap();

        let prover_id = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("Prover选择自身DID和盲化因子blinded_revocation_secrets时间{}ms", time_end - time_start);

        let time_start = chrono::Utc::now().timestamp_millis();

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let revocation_id1 = 1;
        let m2 = Issuer::gen_credential_context(prover_id, Some(revocation_id1)).unwrap();


        let (mut non_revocation_credential_signature1, revocation_registry_delta1) =
            Issuer::add_to_accumulaor(revocation_id1, &m2, max_element_num, &blinded_revocation_secrets, &mut accumulator_pub,
                                      &accumulator_pri_key, &credential_revocation_public_key, &credential_revocation_private_key, &simple_tail_accessor).unwrap();

        let revocation_registry_delta1 = &revocation_registry_delta1.unwrap();
        let mut witness1 = Witness::new(revocation_id1, max_element_num, revocation_registry_delta1, &simple_tail_accessor).unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("issuer生成未撤销证据的证明时间{}ms", time_end - time_start);

        let time_start = chrono::Utc::now().timestamp_millis();
        Prover::check_revocation_credential(&mut non_revocation_credential_signature1,
                                            &blinded_revocation_secrets, &credential_revocation_public_key, &accumulator_pub, &witness1);
        Prover::store_non_revocation_credential(&mut non_revocation_credential_signature1, &blinded_revocation_secrets);
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("Prover对证书和证明验证，对随机数进行偏移并存储时间{}ms", time_end - time_start);
        //let mut proof_builder = Prover::new_proof_builder().unwrap();

        let proof_request_nonce = new_nonce().unwrap();

        let time_start = chrono::Utc::now().timestamp_millis();
        let non_revoc_init_proof = Prover::init_non_revocation_proof(&non_revocation_credential_signature1, &accumulator_pub, &credential_revocation_public_key, &witness1).unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof.as_c_list().unwrap());
        values.push(proof_request_nonce.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge = get_hash_as_int(&values).unwrap();
        let non_revoc_proof = Prover::finalize_non_revocation_proof(&non_revoc_init_proof, &challenge).unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("Prover生成未撤销证明时间{}ms", time_end - time_start);

        let time_start = chrono::Utc::now().timestamp_millis();
        let result = Verifier::verify(challenge, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof, &proof_request_nonce).unwrap();
        assert_eq!(result, true);
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("Verifier验证未撤销证明时间{}ms", time_end - time_start);



        //=======================================================================================//
        //=======================================第二个人的=======================================//
        //=======================================================================================//
        let blinded_revocation_secrets = Prover::generate_blinded_revocation(&credential_revocation_public_key).unwrap();

        let prover_id = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

        let revocation_id2 = 2;
        let m2 = Issuer::gen_credential_context(prover_id, Some(revocation_id2)).unwrap();

        let time_start = chrono::Utc::now().timestamp_millis();
        let (mut non_revocation_credential_signature2, revocation_registry_delta2) =
            Issuer::add_to_accumulaor(revocation_id2, &m2, max_element_num, &blinded_revocation_secrets, &mut accumulator_pub,
                                      &accumulator_pri_key, &credential_revocation_public_key, &credential_revocation_private_key, &simple_tail_accessor).unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("issuer更新聚合值时间{}ms", time_end - time_start);


        let time_start = chrono::Utc::now().timestamp_millis();
        let revocation_registry_delta2 = &revocation_registry_delta2.unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("更新未撤销证据witness时间{}ms", time_end - time_start);
        witness1.update(revocation_id1, max_element_num, revocation_registry_delta2, &simple_tail_accessor).unwrap();


        let mut witness2 = Witness::new(revocation_id2, max_element_num, revocation_registry_delta2, &simple_tail_accessor).unwrap();
        witness2.update(revocation_id2, max_element_num, revocation_registry_delta1, &simple_tail_accessor).unwrap();

        Prover::check_revocation_credential(&mut non_revocation_credential_signature2,
                                            &blinded_revocation_secrets, &credential_revocation_public_key, &accumulator_pub, &witness2);
        Prover::store_non_revocation_credential(&mut non_revocation_credential_signature2, &blinded_revocation_secrets);
        let non_revoc_init_proof2 = Prover::init_non_revocation_proof(&non_revocation_credential_signature2,
                                                                      &accumulator_pub, &credential_revocation_public_key, &witness2).unwrap();
        let proof_request_nonce2 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof2.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof2.as_c_list().unwrap());
        values.push(proof_request_nonce2.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge2 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof2 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof2, &challenge2).unwrap();
        let time_start = chrono::Utc::now().timestamp_millis();
        let result = Verifier::verify(challenge2, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof2, &proof_request_nonce2).unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        assert_eq!(result, true);
        println!("Verifier验证第二个人未撤销证明时间{}ms", time_end - time_start);


        let non_revoc_init_proof1 = Prover::init_non_revocation_proof(&non_revocation_credential_signature1,
                                                                      &accumulator_pub, &credential_revocation_public_key, &witness1).unwrap();
        let proof_request_nonce1 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof1.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof1.as_c_list().unwrap());
        values.push(proof_request_nonce1.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge1 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof1 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof1, &challenge1).unwrap();

        let time_start = chrono::Utc::now().timestamp_millis();
        let result = Verifier::verify(challenge1, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof1, &proof_request_nonce1).unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        assert_eq!(result, true);
        println!("Verifier再次验证第一个人未撤销证明时间{}ms", time_end - time_start);

        let time_start = chrono::Utc::now().timestamp_millis();
        let revocation_registry_delta1 = Issuer::delete_from_accumulaor(revocation_id1, max_element_num, &mut accumulator_pub, &simple_tail_accessor);
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("Issuer删除第一个人未撤销证明时间{}ms", time_end - time_start);

        let non_revoc_init_proof1 = Prover::init_non_revocation_proof(&non_revocation_credential_signature1,
                                                                      &accumulator_pub, &credential_revocation_public_key, &witness1).unwrap();
        let proof_request_nonce1 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof1.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof1.as_c_list().unwrap());
        values.push(proof_request_nonce1.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge1 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof1 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof1, &challenge1).unwrap();
        let time_start = chrono::Utc::now().timestamp_millis();
        let result = Verifier::verify(challenge1, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof1, &proof_request_nonce1).unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        assert_eq!(result, false);
        println!("Verifier再次验证第一个人未撤销证明时间{}ms，此时验证失败", time_end - time_start);


        let time_start = chrono::Utc::now().timestamp_millis();

        let revocation_registry_delta1 = &revocation_registry_delta1.unwrap().unwrap();

        let mut omega_denom = PointG2::new_inf().unwrap();
        for j in revocation_registry_delta1.revoked.iter() {
            if revocation_id2.eq(j) { continue; }


            let index = max_element_num + 1 - j + revocation_id2;
            simple_tail_accessor.access_tail(index, &mut |tail| {
                omega_denom = omega_denom.add(tail).unwrap();
            });
        }
        let time_end = chrono::Utc::now().timestamp_millis();
        assert_eq!(result, false);
        println!("Issuer更新simple_tail_accessor时间{}ms", time_end - time_start);

        let time_start = chrono::Utc::now().timestamp_millis();
        witness2.update(revocation_id2, max_element_num, revocation_registry_delta1, &simple_tail_accessor).unwrap();
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("witness2更新证明时间{}ms", time_end - time_start);

        let non_revoc_init_proof2 = Prover::init_non_revocation_proof(&non_revocation_credential_signature2,
                                                                      &accumulator_pub, &credential_revocation_public_key, &witness2).unwrap();
        let proof_request_nonce2 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof2.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof2.as_c_list().unwrap());
        values.push(proof_request_nonce2.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge2 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof2 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof2, &challenge2).unwrap();

        let time_start = chrono::Utc::now().timestamp_millis();
        let result = Verifier::verify(challenge2, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof2, &proof_request_nonce2).unwrap();
        assert_eq!(result, true);
        let time_end = chrono::Utc::now().timestamp_millis();
        println!("Verifier再次验证第一个人未撤销证明时间{}ms，此时验证成功", time_end - time_start);

        println!("{}", "accumulator demo展示结束".red());
    }

    #[test]
    fn demo_accumulator() {
        println!("{}", "accumulator demo展示开始".green());
        pause();

        println!("{}", "Issuer初始化（需要指定最多证书个数），生成一个新的聚合器".green());
        let max_element_num = 100;
        println!("{}", "Issuer生成公私钥对".green());
        let (credential_revocation_public_key, credential_revocation_private_key) =
            Issuer::new_revocation_keys().unwrap();
        print!("{}", "公钥credentialRevocationPublicKey = ".yellow());
        println!("{:?}", credential_revocation_public_key);
        print!("{}", "私钥credentialRevocationPrivateKey = ".yellow());
        println!("{:?}", credential_revocation_private_key);
        pause();

        println!("{}", "Issuer初始化聚合器公私钥对、聚合值".green());
        let (mut accumulator_pub, accumulator_pri_key) = Issuer::new_accumulator(&credential_revocation_public_key, max_element_num).unwrap();
        print!("{}", "公钥、聚合值accumulator_pub = ".yellow());
        println!("{:?}", accumulator_pub);
        print!("{}", "私钥accumulator_pri_key = ".yellow());
        println!("{:?}", accumulator_pri_key);
        println!("{}", "Issuer将公钥、聚合值公开".green());
        pause();

        let mut rev_tails_generator = RevocationTailsGenerator::new(
            max_element_num,
            accumulator_pri_key.gamma.clone(),
            credential_revocation_public_key.g_dash.clone());
        let simple_tail_accessor = SimpleTailsAccessor::new(&mut rev_tails_generator).unwrap();

        println!("{}", "Prover使用Issuer公钥盲化s'".green());
        let blinded_revocation_secrets = Prover::generate_blinded_revocation(&credential_revocation_public_key).unwrap();
        print!("{}", "盲化因子blindedRevocationSecrets = ".yellow());
        println!("{:?}", blinded_revocation_secrets);
        pause();

        println!("{}", "Prover选择自身DID".green());
        let prover_id = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";
        print!("{}", "DID prover_id = ".yellow());
        println!("{:?}", prover_id);
        println!("{}", "Prover发送自身DID和盲化因子给Issuer".green());
        pause();

        println!("{}", "Issuer开始颁发non-revocation证书".green());
        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let revocation_id1 = 1;
        println!("{}", "Issuer选择一个未分配的revocationID，并计算该Prover的唯一身份标识".green());
        print!("{}", "Prover revocation_id2 = ".yellow());
        println!("{:?}", revocation_id1);
        let m2 = Issuer::gen_credential_context(prover_id, Some(revocation_id1)).unwrap();
        print!("{}", "Prover 唯一身份标识 m2 = ".yellow());
        println!("{:?}", m2);
        pause();


        println!("{}", "Issuer将Prover证据添加至聚合器，生成witness证明".green());
        let (mut non_revocation_credential_signature1, revocation_registry_delta1) =
            Issuer::add_to_accumulaor(revocation_id1, &m2, max_element_num, &blinded_revocation_secrets, &mut accumulator_pub,
                                      &accumulator_pri_key, &credential_revocation_public_key, &credential_revocation_private_key, &simple_tail_accessor).unwrap();
        print!("{}", "未撤销证据的证明nonRevocationCredentialSignature = ".yellow());
        println!("{:?}", non_revocation_credential_signature1);
        pause();

        println!("{}", "Issuer计算未撤销证据".green());
        let revocation_registry_delta1 = &revocation_registry_delta1.unwrap();
        let mut witness1 = Witness::new(revocation_id1, max_element_num, revocation_registry_delta1, &simple_tail_accessor).unwrap();
        print!("{}", "未撤销证据witness = ".yellow());
        println!("{:?}", witness1);
        println!("{}", "Issuer将未撤销证据及其证明发送给Prover".green());
        pause();

        println!("{}", "Prover对证书和证明验证，对随机数进行偏移并存储".green());
        Prover::check_revocation_credential(&mut non_revocation_credential_signature1,
                                            &blinded_revocation_secrets, &credential_revocation_public_key, &accumulator_pub, &witness1);
        Prover::store_non_revocation_credential(&mut non_revocation_credential_signature1, &blinded_revocation_secrets);

        //let mut proof_builder = Prover::new_proof_builder().unwrap();
        println!("{}", "Prover对未撤销证明进行盲化".green());
        let non_revoc_init_proof = Prover::init_non_revocation_proof(&non_revocation_credential_signature1, &accumulator_pub, &credential_revocation_public_key, &witness1).unwrap();

        let proof_request_nonce = new_nonce().unwrap();

        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof.as_c_list().unwrap());
        values.push(proof_request_nonce.to_bytes().unwrap());

        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge = get_hash_as_int(&values).unwrap();

        let non_revoc_proof = Prover::finalize_non_revocation_proof(&non_revoc_init_proof, &challenge).unwrap();
        print!("{}", "Prover盲化后的证据nonRevocProof= ".yellow());
        println!("{:?}", non_revoc_proof);
        println!("{}", "至此，颁发未撤销证据的流程结束".red());
        pause();

        println!("{}", "撤销证据验证流程开始".red());
        println!("{}", "Prover将盲化后的证据和证明发送给Verifier".green());
        println!("{}", "Verifier利用issuer的撤销公钥credentialRevocationPublicKey、聚合器的公钥和聚合值accumulatorPub、挑战challenge、盲化后的证据nonRevocProof、随机值proofRequestNonce进行验证".green());

        print!("{}", "撤销公钥credentialRevocationPublicKey= ".yellow());
        println!("{:?}", credential_revocation_public_key);

        print!("{}", "聚合器的公开信息（公钥和聚合值）accumulator_pub= ".yellow());
        println!("{:?}", accumulator_pub);

        print!("{}", "挑战challenge= ".yellow());
        println!("{:?}", challenge);

        print!("{}", "盲化后的证据nonRevocProof= ".yellow());
        println!("{:?}", non_revoc_proof);

        print!("{}", "随机值proofRequestNonce= ".yellow());
        println!("{:?}", proof_request_nonce);

        println!("{}", "Verifier根据Prover发来的东西进行验证……".green());
        let result = Verifier::verify(challenge, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof, &proof_request_nonce).unwrap();
        print!("{}", "验证结果= ".yellow());
        println!("{:?}", result);


        //=======================================================================================//
        //=======================================第二个人的=======================================//
        //=======================================================================================//
        println!("{}", "为第二个Prover颁发未撤销证书".green());
        let blinded_revocation_secrets = Prover::generate_blinded_revocation(&credential_revocation_public_key).unwrap();
        pause();

        let prover_id = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

        // In the anoncreds whitepaper, `credential context` is denoted by `m2`
        let revocation_id2 = 2;
        let m2 = Issuer::gen_credential_context(prover_id, Some(revocation_id2)).unwrap();

        println!("{}", "现在更新聚合值".green());
        let (mut non_revocation_credential_signature2, revocation_registry_delta2) =
            Issuer::add_to_accumulaor(revocation_id2, &m2, max_element_num, &blinded_revocation_secrets, &mut accumulator_pub,
                                      &accumulator_pri_key, &credential_revocation_public_key, &credential_revocation_private_key, &simple_tail_accessor).unwrap();
        print!("{}", "更新后的聚合值= ".yellow());
        println!("{:?}", accumulator_pub.accumulator);
        pause();


        let revocation_registry_delta2 = &revocation_registry_delta2.unwrap();
        println!("{}", "现在更新第一个人的未撤销证据".green());
        witness1.update(revocation_id1, max_element_num, revocation_registry_delta2, &simple_tail_accessor).unwrap();
        print!("{}", "更新之后第一个人的证据Witness= ".yellow());
        println!("{:?}", witness1);


        println!("{}", "现在更新第二个人的未撤销证据".green());
        let mut witness2 = Witness::new(revocation_id2, max_element_num, revocation_registry_delta2, &simple_tail_accessor).unwrap();
        witness2.update(revocation_id2, max_element_num, revocation_registry_delta1, &simple_tail_accessor).unwrap();
        print!("{}", "更新之后第二个人的证据Witness = ".yellow());
        println!("{:?}", witness2);

        println!("{}", "第二个人向验证者发送未撤销凭证".green());
        Prover::check_revocation_credential(&mut non_revocation_credential_signature2,
                                            &blinded_revocation_secrets, &credential_revocation_public_key, &accumulator_pub, &witness2);
        Prover::store_non_revocation_credential(&mut non_revocation_credential_signature2, &blinded_revocation_secrets);
        let non_revoc_init_proof2 = Prover::init_non_revocation_proof(&non_revocation_credential_signature2,
                                                                      &accumulator_pub, &credential_revocation_public_key, &witness2).unwrap();
        let proof_request_nonce2 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof2.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof2.as_c_list().unwrap());
        values.push(proof_request_nonce2.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge2 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof2 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof2, &challenge2).unwrap();
        pause();

        println!("{}", "Verifier根据Prover发来的东西进行验证……".green());
        let result = Verifier::verify(challenge2, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof2, &proof_request_nonce2).unwrap();
        print!("{}", "第二个人验证结果= ".yellow());
        println!("{:?}", result);


        println!("{}", "第一个人第二次验证（需要用到更新之后的witness、需要重新选择随机数），向验证者发送未撤销凭证".green());

        let non_revoc_init_proof1 = Prover::init_non_revocation_proof(&non_revocation_credential_signature1,
                                                                      &accumulator_pub, &credential_revocation_public_key, &witness1).unwrap();
        let proof_request_nonce1 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof1.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof1.as_c_list().unwrap());
        values.push(proof_request_nonce1.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge1 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof1 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof1, &challenge1).unwrap();
        pause();
        println!("{}", "Verifier根据Prover发来的东西进行验证……".yellow());
        let result = Verifier::verify(challenge1, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof1, &proof_request_nonce1).unwrap();
        print!("{}", "第一个人验证结果= ".yellow());
        println!("{:?}", result);


        println!("{}", "现在撤销第一个人的凭证（即从聚合器中删除）".green());
        let revocation_registry_delta1 = Issuer::delete_from_accumulaor(revocation_id1, max_element_num, &mut accumulator_pub, &simple_tail_accessor);


        print!("{}", "更新后的聚合值= ".yellow());
        println!("{:?}", accumulator_pub.accumulator);
        pause();

        println!("{}", "第一个人第三次验证，将相关数据发送给verifier（此时已经被撤销了，所以应该验证不通过）".green());

        let non_revoc_init_proof1 = Prover::init_non_revocation_proof(&non_revocation_credential_signature1,
                                                                      &accumulator_pub, &credential_revocation_public_key, &witness1).unwrap();
        let proof_request_nonce1 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof1.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof1.as_c_list().unwrap());
        values.push(proof_request_nonce1.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge1 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof1 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof1, &challenge1).unwrap();
        pause();
        println!("{}", "Verifier根据Prover发来的东西进行验证……".green());
        let result = Verifier::verify(challenge1, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof1, &proof_request_nonce1).unwrap();
        print!("{}", "第一个人验证结果= ".green());
        println!("{:?}", result);


        println!("{}", "现在更新第二个人的未撤销证据".green());
        let revocation_registry_delta1 = &revocation_registry_delta1.unwrap().unwrap();

        let mut omega_denom = PointG2::new_inf().unwrap();
        for j in revocation_registry_delta1.revoked.iter() {
            if revocation_id2.eq(j) { continue; }


            let index = max_element_num + 1 - j + revocation_id2;
            simple_tail_accessor.access_tail(index, &mut |tail| {
                omega_denom = omega_denom.add(tail).unwrap();
            });
        }

        witness2.update(revocation_id2, max_element_num, revocation_registry_delta1, &simple_tail_accessor).unwrap();
        pause();
        print!("{}", "更新之后第二个人的证据Witness= ".yellow());
        println!("{:?}", witness2);

        println!("{}", "第二个人向验证者发送未撤销凭证".green());
        let non_revoc_init_proof2 = Prover::init_non_revocation_proof(&non_revocation_credential_signature2,
                                                                      &accumulator_pub, &credential_revocation_public_key, &witness2).unwrap();
        let proof_request_nonce2 = new_nonce().unwrap();
        let mut values: Vec<Vec<u8>> = Vec::new();
        values.extend_from_slice(&non_revoc_init_proof2.as_tau_list().unwrap());
        values.extend_from_slice(&non_revoc_init_proof2.as_c_list().unwrap());
        values.push(proof_request_nonce2.to_bytes().unwrap());
        // In the anoncreds whitepaper, `challenge2` is denoted by `c_h`
        let challenge2 = get_hash_as_int(&values).unwrap();
        let non_revoc_proof2 = Prover::finalize_non_revocation_proof(&non_revoc_init_proof2, &challenge2).unwrap();
        pause();

        println!("{}", "Verifier根据Prover发来的东西进行验证……".green());
        let time1 = format!("{}", chrono::Utc::now().timestamp_millis());
        let time1_int: i32 = time1.parse().unwrap();
        let result = Verifier::verify(challenge2, &credential_revocation_public_key, &accumulator_pub, &non_revoc_proof2, &proof_request_nonce2).unwrap();
        print!("{}", "第二个人验证结果= ".yellow());
        let time2 = format!("{}", chrono::Utc::now().timestamp_millis());
        let time2_int: i32 = time2.parse().unwrap();
        println!("verify time = {}ms", time2_int - time1_int);
        println!("{:?}", result);


        println!("{}", "accumulator demo展示结束".red());
    }
}

fn pause() {
    let mut enter_continue = String::new();
    println!("{}", "Press any key to continue...".green());
    io::stdin().read_line(&mut enter_continue).expect("Failed to read line.");
    println!("continued! {}\n", enter_continue.trim());
}

