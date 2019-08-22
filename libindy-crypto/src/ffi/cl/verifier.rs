use cl::verifier::*;
use cl::*;
use errors::ToErrorCode;
use errors::ErrorCode;

use std::os::raw::c_void;

/// Creates and returns proof verifier.
///
/// Note that proof verifier deallocation must be performed by
/// calling cl_proof_verifier_finalize.
///
/// # Arguments
/// * `proof_verifier_p` - Reference that will contain proof verifier instance pointer.
#[no_mangle]
pub extern fn cl_verifier_new_proof_verifier(proof_verifier_p: *mut *const c_void) -> ErrorCode {
    trace!("cl_verifier_new_proof_verifier: >>> {:?}", proof_verifier_p);

    check_useful_c_ptr!(proof_verifier_p, ErrorCode::CommonInvalidParam1);

    let res = match Verifier::new_proof_verifier() {
        Ok(proof_verifier) => {
            trace!("cl_verifier_new_proof_verifier: proof_verifier: {:?}", proof_verifier);
            unsafe {
                *proof_verifier_p = Box::into_raw(Box::new(proof_verifier)) as *const c_void;
                trace!("cl_verifier_new_proof_verifier: *proof_verifier_p: {:?}", *proof_verifier_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("cl_verifier_new_proof_verifier: <<< res: {:?}", res);
    res
}

#[no_mangle]
pub extern fn cl_proof_verifier_add_sub_proof_request(proof_verifier: *const c_void,
                                                                  sub_proof_request: *const c_void,
                                                                  credential_schema: *const c_void,
                                                                  non_credential_schema: *const c_void,
                                                                  credential_pub_key: *const c_void) -> ErrorCode {
    trace!("cl_proof_verifier_add_sub_proof_request: >>> proof_verifier: {:?}, \
                                                                     sub_proof_request: {:?} ,\
                                                                     credential_schema: {:?}, \
                                                                     non_credential_schema: {:?}, \
                                                                     credential_pub_key: {:?}",
           proof_verifier, sub_proof_request, credential_schema, non_credential_schema, credential_pub_key);

    check_useful_mut_c_reference!(proof_verifier, ProofVerifier, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(sub_proof_request, SubProofRequest, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(credential_schema, CredentialSchema, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(non_credential_schema, NonCredentialSchema, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(credential_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam5);

    trace!("cl_proof_verifier_add_sub_proof_request: entities: proof_verifier: {:?}, sub_proof_request: {:?},\
                credential_schema: {:?}, non_credential_schema: {:?}, credential_pub_key: {:?}",
           proof_verifier, sub_proof_request, credential_schema, non_credential_schema, credential_pub_key);

    let res = match proof_verifier.add_sub_proof_request(sub_proof_request,
                                                         credential_schema,
                                                         non_credential_schema,
                                                         credential_pub_key) {
        Ok(()) => ErrorCode::Success,
        Err(err) => err.to_error_code()
    };

    trace!("cl_proof_verifier_add_sub_proof_request: <<< res: {:?}", res);
    ErrorCode::Success
}


/// Verifies proof and deallocates proof verifier.
///
/// # Arguments
/// * `proof_verifier` - Reference that contain proof verifier instance pointer.
/// * `proof` - Reference that contain proof instance pointer.
/// * `nonce` - Reference that contain nonce instance pointer.
/// * `valid_p` - Reference that will be filled with true - if proof valid or false otherwise.
#[no_mangle]
pub extern fn cl_proof_verifier_verify(proof_verifier: *const c_void,
                                                   proof: *const c_void,
                                                   nonce: *const c_void,
                                                   valid_p: *mut bool) -> ErrorCode {
    trace!("cl_proof_verifier_verify: >>> proof_verifier: {:?}, proof: {:?}, nonce: {:?}, valid_p: {:?}", proof_verifier, proof, nonce, valid_p);

    check_useful_c_ptr!(proof_verifier, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(proof, Proof, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(nonce, Nonce, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(valid_p, ErrorCode::CommonInvalidParam4);

    let proof_verifier = unsafe { Box::from_raw(proof_verifier as *mut ProofVerifier) };

    trace!("cl_proof_verifier_verify: entities: >>> proof_verifier: {:?}, proof: {:?}, nonce: {:?}", proof_verifier, proof, nonce);

    let res = match proof_verifier.verify(proof, nonce) {
        Ok(valid) => {
            trace!("cl_proof_verifier_verify: valid: {:?}", valid);
            unsafe {
                *valid_p = valid;
                trace!("cl_proof_verifier_verify: *valid_p: {:?}", *valid_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("cl_proof_verifier_verify: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ptr;
    use ffi::cl::mocks::*;
    use super::mocks::*;
    use super::super::issuer::mocks::*;
    use super::super::prover::mocks::*;

    #[test]
    fn cl_verifier_new_proof_verifier_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (blinded_credential_secrets, credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof) = _blinded_credential_secrets(credential_pub_key,
                                                                                   credential_key_correctness_proof,
                                                                                   credential_values,
                                                                                   credential_nonce);
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(blinded_credential_secrets,
                                                                                        blinded_credential_secrets_correctness_proof,
                                                                                        credential_nonce,
                                                                                        credential_issuance_nonce,
                                                                                        credential_values,
                                                                                        credential_pub_key,
                                                                                        credential_priv_key);
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();
        _process_credential_signature(credential_signature,
                                      signature_correctness_proof,
                                      credential_secrets_blinding_factors,
                                      credential_values,
                                      credential_pub_key,
                                      credential_issuance_nonce);

        let proof_building_nonce = _nonce();
        let proof = _proof(credential_pub_key,
                           credential_signature,
                           proof_building_nonce,
                           credential_values);

        let mut proof_verifier_p: *const c_void = ptr::null();
        let err_code = cl_verifier_new_proof_verifier(&mut proof_verifier_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_verifier_p.is_null());

        _add_sub_proof_request(proof_verifier_p, credential_schema, non_credential_schema, credential_pub_key, sub_proof_request);
        _free_proof_verifier(proof_verifier_p, proof, proof_building_nonce);
        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_schema(credential_schema);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn cl_proof_verifier_add_sub_proof_request_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (blinded_credential_secrets, credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof) = _blinded_credential_secrets(credential_pub_key,
                                                                                   credential_key_correctness_proof,
                                                                                   credential_values,
                                                                                   credential_nonce);
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(blinded_credential_secrets,
                                                                                        blinded_credential_secrets_correctness_proof,
                                                                                        credential_nonce,
                                                                                        credential_issuance_nonce,
                                                                                        credential_values,
                                                                                        credential_pub_key,
                                                                                        credential_priv_key);
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();
        _process_credential_signature(credential_signature,
                                      signature_correctness_proof,
                                      credential_secrets_blinding_factors,
                                      credential_values,
                                      credential_pub_key,
                                      credential_issuance_nonce);

        let proof_building_nonce = _nonce();
        let proof = _proof(credential_pub_key,
                           credential_signature,
                           proof_building_nonce,
                           credential_values);

        let proof_verifier = _proof_verifier();

        let err_code = cl_proof_verifier_add_sub_proof_request(proof_verifier,
                                                                           sub_proof_request,
                                                                           credential_schema,
                                                                           non_credential_schema,
                                                                           credential_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        _free_proof_verifier(proof_verifier, proof, proof_building_nonce);
        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_schema(credential_schema);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn cl_proof_verifier_verify_works_for_primary_proof() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let credential_values = _credential_values();
        let credential_nonce = _nonce();
        let (blinded_credential_secrets, credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof) = _blinded_credential_secrets(credential_pub_key,
                                                                                   credential_key_correctness_proof,
                                                                                   credential_values,
                                                                                   credential_nonce);
        let credential_issuance_nonce = _nonce();
        let (credential_signature, signature_correctness_proof) = _credential_signature(blinded_credential_secrets,
                                                                                        blinded_credential_secrets_correctness_proof,
                                                                                        credential_nonce,
                                                                                        credential_issuance_nonce,
                                                                                        credential_values,
                                                                                        credential_pub_key,
                                                                                        credential_priv_key);
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let sub_proof_request = _sub_proof_request();
        _process_credential_signature(credential_signature,
                                      signature_correctness_proof,
                                      credential_secrets_blinding_factors,
                                      credential_values,
                                      credential_pub_key,
                                      credential_issuance_nonce);

        let proof_building_nonce = _nonce();
        let proof = _proof(credential_pub_key,
                           credential_signature,
                           proof_building_nonce,
                           credential_values);

        let proof_verifier = _proof_verifier();
        _add_sub_proof_request(proof_verifier, credential_schema, non_credential_schema, credential_pub_key, sub_proof_request);

        let mut valid = false;
        let err_code = cl_proof_verifier_verify(proof_verifier, proof, proof_building_nonce, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(valid);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_nonce(proof_building_nonce);
        _free_credential_schema(credential_schema);
        _free_sub_proof_request(sub_proof_request);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }
}

pub mod mocks {
    use super::*;
    use std::ptr;

    pub fn _proof_verifier() -> *const c_void {
        let mut proof_verifier_p: *const c_void = ptr::null();
        let err_code = cl_verifier_new_proof_verifier(&mut proof_verifier_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!proof_verifier_p.is_null());

        proof_verifier_p
    }

    pub fn _add_sub_proof_request(proof_verifier: *const c_void, credential_schema: *const c_void, non_credential_schema: *const c_void,
                                  credential_pub_key: *const c_void, sub_proof_request: *const c_void) {
        let err_code = cl_proof_verifier_add_sub_proof_request(proof_verifier,
                                                                           sub_proof_request,
                                                                           credential_schema,
                                                                           non_credential_schema,
                                                                           credential_pub_key);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _free_proof_verifier(proof_verifier: *const c_void, proof: *const c_void, nonce: *const c_void) {
        let mut valid = false;
        let err_code = cl_proof_verifier_verify(proof_verifier, proof, nonce, &mut valid);
        assert_eq!(err_code, ErrorCode::Success);
    }
}
