extern crate serde_derive;
extern crate serde_json;
extern crate indy_crypto;

use indy_crypto::cl::new_nonce;
use indy_crypto::cl::issuer::Issuer;
use indy_crypto::cl::prover::Prover;
use indy_crypto::cl::verifier::Verifier;
use self::indy_crypto::cl::logger::IndyCryptoDefaultLogger;

pub const PROVER_ID: &'static str = "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW";

mod test {
    use super::*;
    use indy_crypto::errors::ErrorCode;
    use indy_crypto::errors::ToErrorCode;

    #[test]
    fn anoncreds_works_for_primary_proof_only() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Issuer creates credential values
        let credential_values = helpers::gvt_credential_values(&Prover::new_master_secret().unwrap());

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds hidden attributes
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();


        // 7. Issuer signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             &credential_issuance_nonce).unwrap();

        // 9. Verifier create sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 11. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder.add_sub_proof_request(&sub_proof_request,
                                            &credential_schema,
                                            &non_credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key).unwrap();
        let proof = proof_builder.finalize(&nonce).unwrap();

        // 12. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(&sub_proof_request,
                                             &credential_schema,
                                             &non_credential_schema,
                                             &credential_pub_key).unwrap();
        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_multiple_credentials_used_for_proof() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();

        let gvt_credential_values = helpers::gvt_credential_values(&master_secret);

        // 2. Issuer creates and signs GVT credential for Prover
        let gvt_credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();
        let (gvt_credential_pub_key, gvt_credential_priv_key, gvt_credential_key_correctness_proof) =
            Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema).unwrap();

        let gvt_credential_nonce = new_nonce().unwrap();

        let (gvt_blinded_credential_secrets, gvt_credential_secrets_blinding_factors, gvt_blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&gvt_credential_pub_key,
                                             &gvt_credential_key_correctness_proof,
                                             &gvt_credential_values,
                                             &gvt_credential_nonce).unwrap();

        let gvt_credential_issuance_nonce = new_nonce().unwrap();

        let (mut gvt_credential_signature, gvt_signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                                      &gvt_blinded_credential_secrets,
                                                                                                      &gvt_blinded_credential_secrets_correctness_proof,
                                                                                                      &gvt_credential_nonce,
                                                                                                      &gvt_credential_issuance_nonce,
                                                                                                      &gvt_credential_values,
                                                                                                      &gvt_credential_pub_key,
                                                                                                      &gvt_credential_priv_key).unwrap();

        // 3. Prover processes GVT credential
        Prover::process_credential_signature(&mut gvt_credential_signature,
                                             &gvt_credential_values,
                                             &gvt_signature_correctness_proof,
                                             &gvt_credential_secrets_blinding_factors,
                                             &gvt_credential_pub_key,
                                             &gvt_credential_issuance_nonce).unwrap();

        // 4. Issuer creates and signs XYZ credential for Prover
        let xyz_credential_schema = helpers::xyz_credential_schema();
        let (xyz_credential_pub_key, xyz_credential_priv_key, xyz_credential_key_correctness_proof) =
            Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema).unwrap();

        let xyz_credential_nonce = new_nonce().unwrap();
        let xyz_credential_values = helpers::xyz_credential_values(&master_secret);

        let (xyz_blinded_credential_secrets, xyz_credential_secrets_blinding_factors, xyz_blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&xyz_credential_pub_key,
                                             &xyz_credential_key_correctness_proof,
                                             &xyz_credential_values,
                                             &xyz_credential_nonce).unwrap();

        let xyz_credential_issuance_nonce = new_nonce().unwrap();

        let (mut xyz_credential_signature, xyz_signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                                      &xyz_blinded_credential_secrets,
                                                                                                      &xyz_blinded_credential_secrets_correctness_proof,
                                                                                                      &xyz_credential_nonce,
                                                                                                      &xyz_credential_issuance_nonce,
                                                                                                      &xyz_credential_values,
                                                                                                      &xyz_credential_pub_key,
                                                                                                      &xyz_credential_priv_key).unwrap();

        // 5. Prover processes XYZ credential
        Prover::process_credential_signature(&mut xyz_credential_signature,
                                             &xyz_credential_values,
                                             &xyz_signature_correctness_proof,
                                             &xyz_credential_secrets_blinding_factors,
                                             &xyz_credential_pub_key,
                                             &xyz_credential_issuance_nonce).unwrap();
        // 6. Verifier creates nonce
        let nonce = new_nonce().unwrap();

        // 7. Verifier creates proof request which contains two sub proof requests: GVT and XYZ
        let gvt_sub_proof_request = helpers::gvt_sub_proof_request();
        let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

        // 8. Prover creates proof builder
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();

        // 9. Prover adds GVT sub proof request
        proof_builder.add_sub_proof_request(&gvt_sub_proof_request,
                                            &gvt_credential_schema,
                                            &non_credential_schema,
                                            &gvt_credential_signature,
                                            &gvt_credential_values,
                                            &gvt_credential_pub_key).unwrap();

        // 10. Prover adds XYZ sub proof request
        proof_builder.add_sub_proof_request(&xyz_sub_proof_request,
                                            &xyz_credential_schema,
                                            &non_credential_schema,
                                            &xyz_credential_signature,
                                            &xyz_credential_values,
                                            &xyz_credential_pub_key).unwrap();

        // 11. Prover gets proof which contains sub proofs for GVT and XYZ sub proof requests
        let proof = proof_builder.finalize(&nonce).unwrap();

        // 12. Verifier verifies proof for GVT and XYZ sub proof requests
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(&gvt_sub_proof_request,
                                             &gvt_credential_schema,
                                             &non_credential_schema,
                                             &gvt_credential_pub_key).unwrap();
        proof_verifier.add_sub_proof_request(&xyz_sub_proof_request,
                                             &xyz_credential_schema,
                                             &non_credential_schema,
                                             &xyz_credential_pub_key).unwrap();

        assert!(proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_missed_process_credential_step() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let (credential_signature, _) = Issuer::sign_credential(PROVER_ID,
                                                                &blinded_credential_secrets,
                                                                &blinded_credential_secrets_correctness_proof,
                                                                &credential_nonce,
                                                                &credential_issuance_nonce,
                                                                &credential_values,
                                                                &credential_pub_key,
                                                                &credential_priv_key).unwrap();

        // 8. Verifier creates nonce and sub proof request
        let nonce = new_nonce().unwrap();
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 9. Prover creates proof by sub proof request not corresponded to verifier proof request
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder.add_sub_proof_request(&sub_proof_request,
                                            &credential_schema,
                                            &non_credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key).unwrap();
        let proof = proof_builder.finalize(&nonce).unwrap();

        // 10. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(&sub_proof_request,
                                             &credential_schema,
                                             &non_credential_schema,
                                             &credential_pub_key).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_created_with_wrong_master_secret() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values wrong keys
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             &credential_issuance_nonce).unwrap();

        // 9. Verifier creates nonce and sub proof request
        let nonce = new_nonce().unwrap();
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Prover creates proof by sub proof request not corresponded to verifier proof request
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        let another_master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&another_master_secret);

        proof_builder.add_sub_proof_request(&sub_proof_request,
                                            &credential_schema,
                                            &non_credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key).unwrap();


        let proof = proof_builder.finalize(&nonce).unwrap();

        // 11. Verifier verifies proof
        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(&sub_proof_request,
                                             &credential_schema,
                                             &non_credential_schema,
                                             &credential_pub_key).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce).unwrap());
    }

    #[test]
    fn anoncreds_works_for_used_different_nonce() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values wrong keys
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             &credential_issuance_nonce).unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        // 10. Prover creates proof by sub proof request not corresponded to verifier proof request
        let nonce_for_proof_creation = new_nonce().unwrap();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder.add_sub_proof_request(&sub_proof_request,
                                            &credential_schema,
                                            &non_credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key).unwrap();

        let proof = proof_builder.finalize(&nonce_for_proof_creation).unwrap();

        // 11. Verifier verifies proof
        let nonce_for_proof_verification = new_nonce().unwrap();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(&sub_proof_request,
                                             &credential_schema,
                                             &non_credential_schema,
                                             &credential_pub_key).unwrap();
        assert_eq!(false, proof_verifier.verify(&proof, &nonce_for_proof_verification).unwrap());
    }

    #[test]
    fn anoncreds_works_for_proof_not_correspond_to_verifier_proof_request() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             &credential_issuance_nonce).unwrap();

        // 9. Prover creates proof by sub proof request not corresponded to verifier proof request
        let sub_proof_request = helpers::gvt_sub_proof_request();

        let mut proof_builder = Prover::new_proof_builder().unwrap();
        let nonce = new_nonce().unwrap();

        proof_builder.add_common_attribute("master_secret").unwrap();
        proof_builder.add_sub_proof_request(&sub_proof_request,
                                            &credential_schema,
                                            &non_credential_schema,
                                            &credential_signature,
                                            &credential_values,
                                            &credential_pub_key).unwrap();
        let proof = proof_builder.finalize(&nonce).unwrap();

        // 10. Verifier verifies proof
        let xyz_credential_schema = helpers::xyz_credential_schema();
        let (xyz_credential_pub_key, _, _) = Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema).unwrap();
        let xyz_sub_proof_request = helpers::xyz_sub_proof_request();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
        proof_verifier.add_sub_proof_request(&xyz_sub_proof_request,
                                             &xyz_credential_schema,
                                             &non_credential_schema,
                                             &xyz_credential_pub_key).unwrap();
        let res = proof_verifier.verify(&proof, &nonce);
        assert_eq!(ErrorCode::AnoncredsProofRejected, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_create_keys_works_for_empty_credential_schema() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        let credential_schema = credential_schema_builder.finalize().unwrap();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition(with revocation keys)
        let res = Issuer::new_credential_def(&credential_schema, &non_credential_schema);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_credential_works_for_credential_values_not_correspond_to_issuer_keys() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::xyz_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values not correspondent to issuer keys

        // 8. Issuer signs wrong credential values
        let res = Issuer::sign_credential(PROVER_ID,
                                          &blinded_credential_secrets,
                                          &blinded_credential_secrets_correctness_proof,
                                          &credential_nonce,
                                          &credential_issuance_nonce,
                                          &credential_values,
                                          &credential_pub_key,
                                          &credential_priv_key);

        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_credential_values_not_correspond_to_credential_schema() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             &credential_issuance_nonce).unwrap();

        // 9. Prover creates proof
        let mut proof_builder = Prover::new_proof_builder().unwrap();

        // Wrong credential values
        let credential_values = helpers::xyz_credential_values(&master_secret);

        let sub_proof_request = helpers::gvt_sub_proof_request();

        let res = proof_builder.add_sub_proof_request(&sub_proof_request,
                                                      &credential_schema,
                                                      &non_credential_schema,
                                                      &credential_signature,
                                                      &credential_values,
                                                      &credential_pub_key);

        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_credential_not_satisfy_to_sub_proof_request() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             &credential_issuance_nonce).unwrap();

        // 9. Verifier creates sub proof request
        let sub_proof_request = helpers::xyz_sub_proof_request();

        // 10. Prover creates proof by credential not correspondent to proof request
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();

        let res = proof_builder.add_sub_proof_request(&sub_proof_request,
                                                      &credential_schema,
                                                      &non_credential_schema,
                                                      &credential_signature,
                                                      &credential_values,
                                                      &credential_pub_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_credential_not_contained_requested_attribute() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             &credential_issuance_nonce).unwrap();

        // 9. Verifier creates sub proof request
        let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        sub_proof_request_builder.add_revealed_attr("status").unwrap();
        let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

        // 10. Prover creates proof by credential not contained requested attribute
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();

        let res = proof_builder.add_sub_proof_request(&sub_proof_request,
                                                      &credential_schema,
                                                      &non_credential_schema,
                                                      &credential_signature,
                                                      &credential_values,
                                                      &credential_pub_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_builder_add_sub_proof_works_for_credential_not_satisfied_requested_predicate() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key,
                                             &credential_key_correctness_proof,
                                             &credential_values,
                                             &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates and signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 8. Prover processes credential signature
        Prover::process_credential_signature(&mut credential_signature,
                                             &credential_values,
                                             &signature_correctness_proof,
                                             &credential_secrets_blinding_factors,
                                             &credential_pub_key,
                                             &credential_issuance_nonce).unwrap();

        // 9. Verifier creates sub proof request
        let mut gvt_sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        gvt_sub_proof_request_builder.add_revealed_attr("name").unwrap();
        gvt_sub_proof_request_builder.add_predicate("age", "GE", 50).unwrap();
        let sub_proof_request = gvt_sub_proof_request_builder.finalize().unwrap();

        // 10. Prover creates proof by credential value not satisfied predicate
        let mut proof_builder = Prover::new_proof_builder().unwrap();
        proof_builder.add_common_attribute("master_secret").unwrap();

        let res = proof_builder.add_sub_proof_request(&sub_proof_request,
                                                      &credential_schema,
                                                      &non_credential_schema,
                                                      &credential_signature,
                                                      &credential_values,
                                                      &credential_pub_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn proof_verifier_add_sub_proof_request_works_for_credential_schema_not_satisfied_to_sub_proof_request() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, _, _) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Verifier build proof verifier
        let sub_proof_request = helpers::gvt_sub_proof_request();
        let xyz_credential_schema = helpers::xyz_credential_schema();

        let mut proof_verifier = Verifier::new_proof_verifier().unwrap();

        let res = proof_verifier.add_sub_proof_request(&sub_proof_request,
                                                       &xyz_credential_schema,
                                                       &non_credential_schema,
                                                       &credential_pub_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_blind_credential_secrets_works_for_key_correctness_proof_not_correspond_to_public_key() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 2. Issuer creates GVT credential definition
        let gvt_credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();
        let (gvt_credential_pub_key, _, _) =
            Issuer::new_credential_def(&gvt_credential_schema, &non_credential_schema).unwrap();

        // 3. Issuer creates XYZ credential definition
        let xyz_credential_schema = helpers::xyz_credential_schema();
        let (_, _, xyz_credential_key_correctness_proof) =
            Issuer::new_credential_def(&xyz_credential_schema, &non_credential_schema).unwrap();

        // 4. Issuer creates nonce used Prover to blind master secret
        let gvt_credential_nonce = new_nonce().unwrap();

        // 5. Prover blind master secret by gvt_public_key and xyz_key_correctness_proof
        let res =
            Prover::blind_credential_secrets(&gvt_credential_pub_key,
                                             &xyz_credential_key_correctness_proof,
                                             &credential_values,
                                             &gvt_credential_nonce);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_credential_works_for_prover_used_different_nonce_to_blind_credential_secrets() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        let other_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key, &credential_key_correctness_proof, &credential_values, &other_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values

        // 8. Issuer signs credential values
        let res = Issuer::sign_credential(PROVER_ID,
                                          &blinded_credential_secrets,
                                          &blinded_credential_secrets_correctness_proof,
                                          &credential_nonce,
                                          &credential_issuance_nonce,
                                          &credential_values,
                                          &credential_pub_key,
                                          &credential_priv_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_credential_works_for_keys_not_correspond_to_blinded_credential_secrets_correctness_proof() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates GVT credential definition
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();
        let (gvt_credential_pub_key, _, gvt_credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 2. Issuer creates XYZ credential definition
        let credential_schema = helpers::xyz_credential_schema();
        let (xyz_credential_pub_key, xyz_credential_priv_key, _) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let gvt_credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret by GVT key
        let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&gvt_credential_pub_key, &gvt_credential_key_correctness_proof, &gvt_credential_values, &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values
        let xyz_credential_values = helpers::xyz_credential_values(&master_secret);

        // 8. Issuer signs XYZ credential values for Prover
        let res = Issuer::sign_credential(PROVER_ID,
                                          &blinded_credential_secrets,
                                          &blinded_credential_secrets_correctness_proof,
                                          &credential_nonce,
                                          &credential_issuance_nonce,
                                          &xyz_credential_values,
                                          &xyz_credential_pub_key,
                                          &xyz_credential_priv_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn issuer_sign_credential_works_for_blinded_credential_secrets_not_correspond_to_blinded_credential_secrets_correctness_proof() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates GVT credential definition
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 2. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 3. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 4. Prover blinds master secret
        let (_, _, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key, &credential_key_correctness_proof, &credential_values, &credential_nonce).unwrap();

        // 5. Prover blinds master secret second time
        let (blinded_credential_secrets, _, _) =
            Prover::blind_credential_secrets(&credential_pub_key, &credential_key_correctness_proof, &credential_values, &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values

        // 8. Issuer signs credential values for Prover
        let res = Issuer::sign_credential(PROVER_ID,
                                          &blinded_credential_secrets,
                                          &blinded_credential_secrets_correctness_proof,
                                          &credential_nonce,
                                          &credential_issuance_nonce,
                                          &credential_values,
                                          &credential_pub_key,
                                          &credential_priv_key);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_process_credential_signature_works_for_issuer_used_different_nonce() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key, &credential_key_correctness_proof, &credential_values, &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        let different_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values

        // 8. Issuer signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &different_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 9. Prover processes credential signature
        let res = Prover::process_credential_signature(&mut credential_signature,
                                                       &credential_values,
                                                       &signature_correctness_proof,
                                                       &credential_secrets_blinding_factors,
                                                       &credential_pub_key,
                                                       &credential_issuance_nonce);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_process_credential_signature_works_for_credential_signature_not_correspond_to_signature_correctness_proof() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key, &credential_key_correctness_proof, &credential_values, &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        let different_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values

        // 8. Issuer signs credential values
        let (mut credential_signature, _) = Issuer::sign_credential(PROVER_ID,
                                                                    &blinded_credential_secrets,
                                                                    &blinded_credential_secrets_correctness_proof,
                                                                    &credential_nonce,
                                                                    &different_nonce,
                                                                    &credential_values,
                                                                    &credential_pub_key,
                                                                    &credential_priv_key).unwrap();

        // 9. Issuer signs credential values second time
        let (_, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                       &blinded_credential_secrets,
                                                                       &blinded_credential_secrets_correctness_proof,
                                                                       &credential_nonce,
                                                                       &different_nonce,
                                                                       &credential_values,
                                                                       &credential_pub_key,
                                                                       &credential_priv_key).unwrap();

        // 10. Prover processes credential signature
        let res = Prover::process_credential_signature(&mut credential_signature,
                                                       &credential_values,
                                                       &signature_correctness_proof,
                                                       &credential_secrets_blinding_factors,
                                                       &credential_pub_key,
                                                       &credential_issuance_nonce);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_process_credential_signature_works_for_credential_secrets_blinding_factors_not_correspond_to_signature() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, _, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key, &credential_key_correctness_proof, &credential_values, &credential_nonce).unwrap();

        // 6. Prover blinds master secret second time
        let (_, credential_secrets_blinding_factors, _) =
            Prover::blind_credential_secrets(&credential_pub_key, &credential_key_correctness_proof, &credential_values, &credential_nonce).unwrap();

        // 7. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 8. Issuer creates credential values

        // 9. Issuer signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        // 10. Prover processes credential signature
        let res = Prover::process_credential_signature(&mut credential_signature,
                                                       &credential_values,
                                                       &signature_correctness_proof,
                                                       &credential_secrets_blinding_factors,
                                                       &credential_pub_key,
                                                       &credential_issuance_nonce);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }

    #[test]
    fn prover_process_credential_signature_works_for_use_different_nonce() {
        IndyCryptoDefaultLogger::init(None).ok();

        // 1. Issuer creates credential schema
        let credential_schema = helpers::gvt_credential_schema();
        let non_credential_schema = helpers::non_credential_schema();

        // 2. Issuer creates credential definition
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = Issuer::new_credential_def(&credential_schema, &non_credential_schema).unwrap();

        // 3. Prover creates master secret
        let master_secret = Prover::new_master_secret().unwrap();
        let credential_values = helpers::gvt_credential_values(&master_secret);

        // 4. Issuer creates nonce used Prover to blind master secret
        let credential_nonce = new_nonce().unwrap();

        // 5. Prover blinds master secret
        let (blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof) =
            Prover::blind_credential_secrets(&credential_pub_key, &credential_key_correctness_proof, &credential_values, &credential_nonce).unwrap();

        // 6. Prover creates nonce used Issuer to credential issue
        let credential_issuance_nonce = new_nonce().unwrap();

        // 7. Issuer creates credential values

        // 8. Issuer signs credential values
        let (mut credential_signature, signature_correctness_proof) = Issuer::sign_credential(PROVER_ID,
                                                                                              &blinded_credential_secrets,
                                                                                              &blinded_credential_secrets_correctness_proof,
                                                                                              &credential_nonce,
                                                                                              &credential_issuance_nonce,
                                                                                              &credential_values,
                                                                                              &credential_pub_key,
                                                                                              &credential_priv_key).unwrap();

        let other_nonce = new_nonce().unwrap();

        // 9. Prover processes credential signature
        let res = Prover::process_credential_signature(&mut credential_signature,
                                                       &credential_values,
                                                       &signature_correctness_proof,
                                                       &credential_secrets_blinding_factors,
                                                       &credential_pub_key,
                                                       &other_nonce);
        assert_eq!(ErrorCode::CommonInvalidStructure, res.unwrap_err().to_error_code());
    }
}

mod helpers {
    use super::*;
    use indy_crypto::cl::*;

    pub fn gvt_credential_schema() -> CredentialSchema {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("name").unwrap();
        credential_schema_builder.add_attr("sex").unwrap();
        credential_schema_builder.add_attr("age").unwrap();
        credential_schema_builder.add_attr("height").unwrap();
        credential_schema_builder.finalize().unwrap()
    }

    pub fn xyz_credential_schema() -> CredentialSchema {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();
        credential_schema_builder.add_attr("status").unwrap();
        credential_schema_builder.add_attr("period").unwrap();
        credential_schema_builder.finalize().unwrap()
    }

    pub fn non_credential_schema() -> NonCredentialSchema {
        let mut non_credential_schema_builder = Issuer::new_non_credential_schema_builder().unwrap();
        non_credential_schema_builder.add_attr("master_secret").unwrap();
        non_credential_schema_builder.finalize().unwrap()
    }

    pub fn gvt_credential_values(master_secret: &MasterSecret) -> CredentialValues {
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value_known("master_secret", &master_secret.value().unwrap()).unwrap();
        credential_values_builder.add_dec_known("name", "1139481716457488690172217916278103335").unwrap();
        credential_values_builder.add_dec_known("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103").unwrap();
        credential_values_builder.add_dec_known("age", "28").unwrap();
        credential_values_builder.add_dec_known("height", "175").unwrap();
        credential_values_builder.finalize().unwrap()
    }

    pub fn xyz_credential_values(master_secret: &MasterSecret) -> CredentialValues {
        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        credential_values_builder.add_value_known("master_secret", &master_secret.value().unwrap()).unwrap();
        credential_values_builder.add_dec_known("status", "51792877103171595686471452153480627530895").unwrap();
        credential_values_builder.add_dec_known("period", "8").unwrap();
        credential_values_builder.finalize().unwrap()
    }

    pub fn gvt_sub_proof_request() -> SubProofRequest {
        let mut gvt_sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        gvt_sub_proof_request_builder.add_revealed_attr("name").unwrap();
        gvt_sub_proof_request_builder.add_predicate("age", "GE", 18).unwrap();
        gvt_sub_proof_request_builder.finalize().unwrap()
    }

    pub fn xyz_sub_proof_request() -> SubProofRequest {
        let mut xyz_sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();
        xyz_sub_proof_request_builder.add_revealed_attr("status").unwrap();
        xyz_sub_proof_request_builder.add_predicate("period", "GE", 4).unwrap();
        xyz_sub_proof_request_builder.finalize().unwrap()
    }
}

