use cl::issuer::*;
use cl::*;
use errors::ToErrorCode;
use errors::ErrorCode;
use ffi::ctypes::CTypesUtils;
use libc::c_char;

use serde_json;
use std::os::raw::c_void;


/// Creates and returns credential definition (public and private keys, correctness proof) entities.
///
/// Note that credential public key instances deallocation must be performed by
/// calling cl_credential_public_key_free.
///
/// Note that credential private key instances deallocation must be performed by
/// calling cl_credential_private_key_free.
///
/// Note that credential key correctness proof instances deallocation must be performed by
/// calling cl_credential_key_correctness_proof_free.
///
/// # Arguments
/// * `credential_schema` - Reference that contains credential schema instance pointer.
/// * `non_credential_schema` - Reference that contains non credential schema instance pointer
/// * `credential_pub_key_p` - Reference that will contain credential public key instance pointer.
/// * `credential_priv_key_p` - Reference that will contain credential private key instance pointer.
/// * `credential_key_correctness_proof_p` - Reference that will contain credential keys correctness proof instance pointer.
#[no_mangle]
pub extern fn cl_issuer_new_credential_def(credential_schema: *const c_void,
                                                       non_credential_schema: *const c_void,
                                                       credential_pub_key_p: *mut *const c_void,
                                                       credential_priv_key_p: *mut *const c_void,
                                                       credential_key_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("cl_issuer_new_credential_def: >>> credential_schema: {:?}, \
                                                          non_credential_schema: {:?}, \
                                                          credential_pub_key_p: {:?}, \
                                                          credential_priv_key_p: {:?},\
                                                          credential_key_correctness_proof_p: {:?}",
                            credential_schema,
                            non_credential_schema,
                            credential_pub_key_p,
                            credential_priv_key_p,
                            credential_key_correctness_proof_p);

    check_useful_c_reference!(credential_schema, CredentialSchema, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(non_credential_schema, NonCredentialSchema, ErrorCode::CommonInvalidParam2);
    check_useful_c_ptr!(credential_pub_key_p, ErrorCode::CommonInvalidParam3);
    check_useful_c_ptr!(credential_priv_key_p, ErrorCode::CommonInvalidParam4);
    check_useful_c_ptr!(credential_key_correctness_proof_p, ErrorCode::CommonInvalidParam5);

    trace!("cl_issuer_new_credential_def: entities: \
                                                      credential_schema: {:?}, \
                                                      non_credential_schema: {:?}, ", credential_schema, non_credential_schema);

    let res = match Issuer::new_credential_def(credential_schema, non_credential_schema) {
        Ok((credential_pub_key, credential_priv_key, credential_key_correctness_proof)) => {
            trace!("cl_issuer_new_credential_def: credential_pub_key: {:?}, credential_priv_key: {:?}, credential_key_correctness_proof: {:?}",
                   credential_pub_key, secret!(&credential_priv_key), credential_key_correctness_proof);
            unsafe {
                *credential_pub_key_p = Box::into_raw(Box::new(credential_pub_key)) as *const c_void;
                *credential_priv_key_p = Box::into_raw(Box::new(credential_priv_key)) as *const c_void;
                *credential_key_correctness_proof_p = Box::into_raw(Box::new(credential_key_correctness_proof)) as *const c_void;
                trace!("cl_issuer_new_credential_def: *credential_pub_key_p: {:?}, *credential_priv_key_p: {:?}, *credential_key_correctness_proof_p: {:?}",
                       *credential_pub_key_p, *credential_priv_key_p, *credential_key_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("cl_issuer_new_credential_def: <<< res: {:?}", res);
    res
}

/// Returns json representation of credential public key.
///
/// # Arguments
/// * `credential_pub_key` - Reference that contains credential public key instance pointer.
/// * `credential_pub_key_p` - Reference that will contain credential public key json.
#[no_mangle]
pub extern fn cl_credential_public_key_to_json(credential_pub_key: *const c_void,
                                                           credential_pub_key_json_p: *mut *const c_char) -> ErrorCode {
    trace!("cl_credential_public_key_to_json: >>> credential_pub_key: {:?}, credential_pub_key_json_p: {:?}", credential_pub_key, credential_pub_key_json_p);

    check_useful_c_reference!(credential_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_pub_key_json_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_credential_public_key_to_json: entity >>> credential_pub_key: {:?}", credential_pub_key);

    let res = match serde_json::to_string(credential_pub_key) {
        Ok(credential_pub_key_json) => {
            trace!("cl_credential_public_key_to_json: credential_pub_key_json: {:?}", credential_pub_key_json);
            unsafe {
                let issuer_pub_key_json = CTypesUtils::string_to_cstring(credential_pub_key_json);
                *credential_pub_key_json_p = issuer_pub_key_json.into_raw();
                trace!("cl_credential_private_key_to_json: credential_pub_key_json_p: {:?}", *credential_pub_key_json_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidState
    };

    trace!("cl_credential_public_key_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns credential public key from json.
///
/// Note: Credential public key instance deallocation must be performed
/// by calling cl_credential_public_key_free
///
/// # Arguments
/// * `credential_pub_key_json` - Reference that contains credential public key json.
/// * `credential_pub_key_p` - Reference that will contain credential public key instance pointer.
#[no_mangle]
pub extern fn cl_credential_public_key_from_json(credential_pub_key_json: *const c_char,
                                                             credential_pub_key_p: *mut *const c_void) -> ErrorCode {
    trace!("cl_credential_public_key_from_json: >>> credential_pub_key_json: {:?}, credential_pub_key_p: {:?}", credential_pub_key_json, credential_pub_key_p);

    check_useful_c_str!(credential_pub_key_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_pub_key_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_credential_public_key_from_json: entity: credential_pub_key_json: {:?}", credential_pub_key_json);

    let res = match serde_json::from_str::<CredentialPublicKey>(&credential_pub_key_json) {
        Ok(credential_pub_key) => {
            trace!("cl_credential_public_key_from_json: credential_pub_key: {:?}", credential_pub_key);
            unsafe {
                *credential_pub_key_p = Box::into_raw(Box::new(credential_pub_key)) as *const c_void;
                trace!("cl_credential_public_key_from_json: *credential_pub_key_p: {:?}", *credential_pub_key_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidStructure
    };

    trace!("cl_credential_public_key_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates credential public key instance.
///
/// # Arguments
/// * `credential_pub_key` - Reference that contains credential public key instance pointer.
#[no_mangle]
pub extern fn cl_credential_public_key_free(credential_pub_key: *const c_void) -> ErrorCode {
    trace!("cl_credential_public_key_free: >>> credential_pub_key: {:?}", credential_pub_key);

    check_useful_c_ptr!(credential_pub_key, ErrorCode::CommonInvalidParam1);

    let credential_pub_key = unsafe { Box::from_raw(credential_pub_key as *mut CredentialPublicKey); };
    trace!("cl_credential_public_key_free: entity: credential_pub_key: {:?}", credential_pub_key);

    let res = ErrorCode::Success;

    trace!("cl_credential_public_key_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of credential private key.
///
/// # Arguments
/// * `credential_priv_key` - Reference that contains credential private key instance pointer.
/// * `credential_pub_key_p` - Reference that will contain credential private key json.
#[no_mangle]
pub extern fn cl_credential_private_key_to_json(credential_priv_key: *const c_void,
                                                            credential_priv_key_json_p: *mut *const c_char) -> ErrorCode {
    trace!("cl_credential_private_key_to_json: >>> credential_priv_key: {:?}, credential_priv_key_json_p: {:?}", credential_priv_key, credential_priv_key_json_p);

    check_useful_c_reference!(credential_priv_key, CredentialPrivateKey, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_priv_key_json_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_credential_private_key_to_json: entity >>> credential_priv_key: {:?}", secret!(&credential_priv_key));

    let res = match serde_json::to_string(credential_priv_key) {
        Ok(credential_priv_key_json) => {
            trace!("cl_credential_private_key_to_json: credential_priv_key_json: {:?}", secret!(&credential_priv_key_json));
            unsafe {
                let credential_priv_key_json = CTypesUtils::string_to_cstring(credential_priv_key_json);
                *credential_priv_key_json_p = credential_priv_key_json.into_raw();
                trace!("cl_credential_private_key_to_json: credential_priv_key_json_p: {:?}", *credential_priv_key_json_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidState
    };

    trace!("cl_credential_private_key_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns credential private key from json.
///
/// Note: Credential private key instance deallocation must be performed
/// by calling cl_credential_private_key_free
///
/// # Arguments
/// * `credential_priv_key_json` - Reference that contains credential private key json.
/// * `credential_priv_key_p` - Reference that will contain credential private key instance pointer.
#[no_mangle]
pub extern fn cl_credential_private_key_from_json(credential_priv_key_json: *const c_char,
                                                              credential_priv_key_p: *mut *const c_void) -> ErrorCode {
    trace!("cl_credential_private_key_from_json: >>> credential_priv_key_json: {:?}, credential_priv_key_p: {:?}", credential_priv_key_json, credential_priv_key_p);

    check_useful_c_str!(credential_priv_key_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_priv_key_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_credential_private_key_from_json: entity: credential_priv_key_json: {:?}", secret!(&credential_priv_key_json));

    let res = match serde_json::from_str::<CredentialPrivateKey>(&credential_priv_key_json) {
        Ok(credential_priv_key) => {
            trace!("cl_credential_private_key_from_json: credential_priv_key: {:?}", secret!(&credential_priv_key));
            unsafe {
                *credential_priv_key_p = Box::into_raw(Box::new(credential_priv_key)) as *const c_void;
                trace!("cl_credential_private_key_from_json: *credential_priv_key_p: {:?}", *credential_priv_key_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidStructure
    };

    trace!("cl_credential_private_key_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates credential private key instance.
///
/// # Arguments
/// * `credential_priv_key` - Reference that contains credential private key instance pointer.
#[no_mangle]
pub extern fn cl_credential_private_key_free(credential_priv_key: *const c_void) -> ErrorCode {
    trace!("cl_credential_private_key_free: >>> credential_priv_key: {:?}", credential_priv_key);

    check_useful_c_ptr!(credential_priv_key, ErrorCode::CommonInvalidParam1);

    let _credential_priv_key = unsafe { Box::from_raw(credential_priv_key as *mut CredentialPrivateKey); };
    trace!("cl_credential_private_key_free: entity: credential_priv_key: {:?}", secret!(_credential_priv_key));

    let res = ErrorCode::Success;

    trace!("cl_credential_private_key_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of credential key correctness proof.
///
/// # Arguments
/// * `credential_key_correctness_proof` - Reference that contains credential key correctness proof instance pointer.
/// * `credential_key_correctness_proof_p` - Reference that will contain credential key correctness proof json.
#[no_mangle]
pub extern fn cl_credential_key_correctness_proof_to_json(credential_key_correctness_proof: *const c_void,
                                                                      credential_key_correctness_proof_json_p: *mut *const c_char) -> ErrorCode {
    trace!("cl_credential_key_correctness_proof_to_json: >>> credential_key_correctness_proof: {:?}, credential_key_correctness_proof_p: {:?}",
           credential_key_correctness_proof, credential_key_correctness_proof_json_p);

    check_useful_c_reference!(credential_key_correctness_proof, CredentialKeyCorrectnessProof, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_key_correctness_proof_json_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_credential_key_correctness_proof_to_json: entity >>> credential_key_correctness_proof: {:?}", credential_key_correctness_proof);

    let res = match serde_json::to_string(credential_key_correctness_proof) {
        Ok(credential_key_correctness_proof_json) => {
            trace!("cl_credential_key_correctness_proof_to_json: credential_key_correctness_proof_json: {:?}", credential_key_correctness_proof_json);
            unsafe {
                let credential_key_correctness_proof_json = CTypesUtils::string_to_cstring(credential_key_correctness_proof_json);
                *credential_key_correctness_proof_json_p = credential_key_correctness_proof_json.into_raw();
                trace!("cl_credential_key_correctness_proof_to_json: credential_key_correctness_proof_json_p: {:?}", *credential_key_correctness_proof_json_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidState
    };

    trace!("cl_credential_key_correctness_proof_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns credential key correctness proof from json.
///
/// Note: Credential key correctness proof instance deallocation must be performed
/// by calling cl_credential_key_correctness_proof_free
///
/// # Arguments
/// * `credential_key_correctness_proof_json` - Reference that contains credential key correctness proof json.
/// * `credential_key_correctness_proof_p` - Reference that will contain credential key correctness proof instance pointer.
#[no_mangle]
pub extern fn cl_credential_key_correctness_proof_from_json(credential_key_correctness_proof_json: *const c_char,
                                                                        credential_key_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("cl_credential_key_correctness_proof_from_json: >>> credential_key_correctness_proof_json: {:?}, credential_key_correctness_proof_p: {:?}",
           credential_key_correctness_proof_json, credential_key_correctness_proof_p);

    check_useful_c_str!(credential_key_correctness_proof_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_key_correctness_proof_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_credential_key_correctness_proof_from_json: entity: credential_key_correctness_proof_json: {:?}", credential_key_correctness_proof_json);

    let res = match serde_json::from_str::<CredentialKeyCorrectnessProof>(&credential_key_correctness_proof_json) {
        Ok(credential_key_correctness_proof) => {
            trace!("cl_credential_key_correctness_proof_from_json: credential_key_correctness_proof: {:?}", credential_key_correctness_proof);
            unsafe {
                *credential_key_correctness_proof_p = Box::into_raw(Box::new(credential_key_correctness_proof)) as *const c_void;
                trace!("cl_credential_key_correctness_proof_from_json: *credential_key_correctness_proof_p: {:?}", *credential_key_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidStructure
    };

    trace!("cl_credential_key_correctness_proof_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates credential key correctness proof instance.
///
/// # Arguments
/// * `credential_key_correctness_proof` - Reference that contains credential key correctness proof instance pointer.
#[no_mangle]
pub extern fn cl_credential_key_correctness_proof_free(credential_key_correctness_proof: *const c_void) -> ErrorCode {
    trace!("cl_credential_key_correctness_proof_free: >>> credential_key_correctness_proof: {:?}", credential_key_correctness_proof);

    check_useful_c_ptr!(credential_key_correctness_proof, ErrorCode::CommonInvalidParam1);

    let credential_key_correctness_proof = unsafe { Box::from_raw(credential_key_correctness_proof as *mut CredentialKeyCorrectnessProof); };
    trace!("cl_credential_key_correctness_proof_free: entity: credential_key_correctness_proof: {:?}", credential_key_correctness_proof);

    let res = ErrorCode::Success;

    trace!("cl_credential_key_correctness_proof_free: <<< res: {:?}", res);
    res
}

/// Signs credential values with primary keys only.
///
/// Note that credential signature instances deallocation must be performed by
/// calling cl_credential_signature_free.
///
/// Note that credential signature correctness proof instances deallocation must be performed by
/// calling cl_signature_correctness_proof_free.
///
/// # Arguments
/// * `prover_id` - Prover identifier.
/// * `blinded_credential_secrets` - Blinded master secret instance pointer generated by Prover.
/// * `blinded_credential_secrets_correctness_proof` - Blinded master secret correctness proof instance pointer.
/// * `credential_nonce` - Nonce instance pointer used for verification of blinded_credential_secrets_correctness_proof.
/// * `credential_issuance_nonce` - Nonce instance pointer used for creation of signature_correctness_proof.
/// * `credential_values` - Credential values to be signed instance pointer.
/// * `credential_pub_key` - Credential public key instance pointer.
/// * `credential_priv_key` - Credential private key instance pointer.
/// * `credential_signature_p` - Reference that will contain credential signature instance pointer.
/// * `credential_signature_correctness_proof_p` - Reference that will contain credential signature correctness proof instance pointer.
#[no_mangle]
pub extern fn cl_issuer_sign_credential(prover_id: *const c_char,
                                                    blinded_credential_secrets: *const c_void,
                                                    blinded_credential_secrets_correctness_proof: *const c_void,
                                                    credential_nonce: *const c_void,
                                                    credential_issuance_nonce: *const c_void,
                                                    credential_values: *const c_void,
                                                    credential_pub_key: *const c_void,
                                                    credential_priv_key: *const c_void,
                                                    credential_signature_p: *mut *const c_void,
                                                    credential_signature_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?}, \
        credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}, \
        credential_signature_p: {:?}, credential_signature_correctness_proof_p: {:?}",
           prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof,
           credential_nonce, credential_issuance_nonce, credential_values, credential_pub_key, credential_priv_key,
           credential_signature_p, credential_signature_correctness_proof_p);

    check_useful_c_str!(prover_id, ErrorCode::CommonInvalidParam1);
    check_useful_c_reference!(blinded_credential_secrets, BlindedCredentialSecrets, ErrorCode::CommonInvalidParam2);
    check_useful_c_reference!(blinded_credential_secrets_correctness_proof, BlindedCredentialSecretsCorrectnessProof, ErrorCode::CommonInvalidParam3);
    check_useful_c_reference!(credential_nonce, Nonce, ErrorCode::CommonInvalidParam4);
    check_useful_c_reference!(credential_issuance_nonce, Nonce, ErrorCode::CommonInvalidParam5);
    check_useful_c_reference!(credential_values, CredentialValues, ErrorCode::CommonInvalidParam6);
    check_useful_c_reference!(credential_pub_key, CredentialPublicKey, ErrorCode::CommonInvalidParam7);
    check_useful_c_reference!(credential_priv_key, CredentialPrivateKey, ErrorCode::CommonInvalidParam8);
    check_useful_c_ptr!(credential_signature_p, ErrorCode::CommonInvalidParam10);
    check_useful_c_ptr!(credential_signature_correctness_proof_p, ErrorCode::CommonInvalidParam11);

    trace!("cl_issuer_sign_credential: >>> prover_id: {:?}, blinded_credential_secrets: {:?}, blinded_credential_secrets_correctness_proof: {:?},\
     credential_nonce: {:?}, credential_issuance_nonce: {:?}, credential_values: {:?}, credential_pub_key: {:?}, credential_priv_key: {:?}",
           prover_id, blinded_credential_secrets, blinded_credential_secrets_correctness_proof, credential_nonce, credential_issuance_nonce,
           secret!(&credential_values), credential_pub_key, secret!(&credential_priv_key));

    let res = match Issuer::sign_credential(&prover_id,
                                            &blinded_credential_secrets,
                                            &blinded_credential_secrets_correctness_proof,
                                            &credential_nonce,
                                            &credential_issuance_nonce,
                                            &credential_values,
                                            &credential_pub_key,
                                            &credential_priv_key) {
        Ok((credential_signature, credential_signature_correctness_proof)) => {
            trace!("cl_issuer_sign_credential: credential_signature: {:?}, credential_signature_correctness_proof: {:?}",
                   secret!(&credential_signature), credential_signature_correctness_proof);
            unsafe {
                *credential_signature_p = Box::into_raw(Box::new(credential_signature)) as *const c_void;
                *credential_signature_correctness_proof_p = Box::into_raw(Box::new(credential_signature_correctness_proof)) as *const c_void;
                trace!("cl_issuer_sign_credential: *credential_signature_p: {:?}, *credential_signature_correctness_proof_p: {:?}",
                       *credential_signature_p, *credential_signature_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(err) => err.to_error_code()
    };

    trace!("cl_issuer_sign_credential: <<< res: {:?}", res);
    ErrorCode::Success
}

/// Returns json representation of credential signature.
///
/// # Arguments
/// * `credential_signature` - Reference that contains credential signature pointer.
/// * `credential_signature_json_p` - Reference that will contain credential signature json.
#[no_mangle]
pub extern fn cl_credential_signature_to_json(credential_signature: *const c_void,
                                                          credential_signature_json_p: *mut *const c_char) -> ErrorCode {
    trace!("cl_credential_signature_to_json: >>> credential_signature: {:?}, credential_signature_json_p: {:?}",
           credential_signature, credential_signature_json_p);

    check_useful_c_reference!(credential_signature, CredentialSignature, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_signature_json_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_credential_signature_to_json: entity >>> credential_signature: {:?}", secret!(&credential_signature));

    let res = match serde_json::to_string(credential_signature) {
        Ok(credential_signature_json) => {
            trace!("cl_credential_signature_to_json: credential_signature_json: {:?}", secret!(&credential_signature_json));
            unsafe {
                let credential_signature_json = CTypesUtils::string_to_cstring(credential_signature_json);
                *credential_signature_json_p = credential_signature_json.into_raw();
                trace!("cl_credential_signature_to_json: credential_signature_json_p: {:?}", *credential_signature_json_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidState
    };

    trace!("cl_credential_signature_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns credential signature from json.
///
/// Note: Credential signature instance deallocation must be performed
/// by calling cl_credential_signature_free
///
/// # Arguments
/// * `credential_signature_json` - Reference that contains credential signature json.
/// * `credential_signature_p` - Reference that will contain credential signature instance pointer.
#[no_mangle]
pub extern fn cl_credential_signature_from_json(credential_signature_json: *const c_char,
                                                            credential_signature_p: *mut *const c_void) -> ErrorCode {
    trace!("cl_credential_signature_from_json: >>> credential_signature_json: {:?}, credential_signature_p: {:?}",
           credential_signature_json, credential_signature_p);

    check_useful_c_str!(credential_signature_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(credential_signature_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_credential_signature_from_json: entity: credential_signature_json: {:?}", secret!(&credential_signature_json));

    let res = match serde_json::from_str::<CredentialSignature>(&credential_signature_json) {
        Ok(credential_signature) => {
            trace!("cl_credential_signature_from_json: credential_signature: {:?}", secret!(&credential_signature));
            unsafe {
                *credential_signature_p = Box::into_raw(Box::new(credential_signature)) as *const c_void;
                trace!("cl_credential_signature_from_json: *credential_signature_p: {:?}", *credential_signature_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidStructure
    };

    trace!("cl_credential_signature_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates credential signature signature instance.
///
/// # Arguments
/// * `credential_signature` - Reference that contains credential signature instance pointer.
#[no_mangle]
pub extern fn cl_credential_signature_free(credential_signature: *const c_void) -> ErrorCode {
    trace!("cl_credential_signature_free: >>> credential_signature: {:?}", credential_signature);

    check_useful_c_ptr!(credential_signature, ErrorCode::CommonInvalidParam1);

    let _credential_signature = unsafe { Box::from_raw(credential_signature as *mut CredentialSignature); };
    trace!("cl_credential_signature_free: entity: credential_signature: {:?}", secret!(_credential_signature));
    let res = ErrorCode::Success;

    trace!("cl_credential_signature_free: <<< res: {:?}", res);
    res
}

/// Returns json representation of signature correctness proof.
///
/// # Arguments
/// * `signature_correctness_proof` - Reference that contains signature correctness proof instance pointer.
/// * `signature_correctness_proof_json_p` - Reference that will contain signature correctness proof json.
#[no_mangle]
pub extern fn cl_signature_correctness_proof_to_json(signature_correctness_proof: *const c_void,
                                                                 signature_correctness_proof_json_p: *mut *const c_char) -> ErrorCode {
    trace!("cl_signature_correctness_proof_to_json: >>> signature_correctness_proof: {:?}, signature_correctness_proof_json_p: {:?}",
           signature_correctness_proof, signature_correctness_proof_json_p);

    check_useful_c_reference!(signature_correctness_proof, SignatureCorrectnessProof, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(signature_correctness_proof_json_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_signature_correctness_proof_to_json: entity >>> signature_correctness_proof: {:?}", signature_correctness_proof);

    let res = match serde_json::to_string(signature_correctness_proof) {
        Ok(signature_correctness_proof_json) => {
            trace!("cl_signature_correctness_proof_to_json: signature_correctness_proof_json: {:?}", signature_correctness_proof_json);
            unsafe {
                let signature_correctness_proof_json = CTypesUtils::string_to_cstring(signature_correctness_proof_json);
                *signature_correctness_proof_json_p = signature_correctness_proof_json.into_raw();
                trace!("cl_signature_correctness_proof_to_json: signature_correctness_proof_json_p: {:?}", *signature_correctness_proof_json_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidState
    };

    trace!("cl_signature_correctness_proof_to_json: <<< res: {:?}", res);
    res
}

/// Creates and returns signature correctness proof from json.
///
/// Note: Signature correctness proof instance deallocation must be performed
/// by calling cl_signature_correctness_proof_free
///
/// # Arguments
/// * `signature_correctness_proof_json` - Reference that contains signature correctness proof json.
/// * `signature_correctness_proof_p` - Reference that will contain signature correctness proof instance pointer.
#[no_mangle]
pub extern fn cl_signature_correctness_proof_from_json(signature_correctness_proof_json: *const c_char,
                                                                   signature_correctness_proof_p: *mut *const c_void) -> ErrorCode {
    trace!("cl_signature_correctness_proof_from_json: >>> signature_correctness_proof_json: {:?}, signature_correctness_proof_p: {:?}",
           signature_correctness_proof_json, signature_correctness_proof_p);

    check_useful_c_str!(signature_correctness_proof_json, ErrorCode::CommonInvalidParam1);
    check_useful_c_ptr!(signature_correctness_proof_p, ErrorCode::CommonInvalidParam2);

    trace!("cl_signature_correctness_proof_from_json: entity: signature_correctness_proof_json: {:?}", signature_correctness_proof_json);

    let res = match serde_json::from_str::<SignatureCorrectnessProof>(&signature_correctness_proof_json) {
        Ok(signature_correctness_proof) => {
            trace!("cl_signature_correctness_proof_from_json: signature_correctness_proof: {:?}", signature_correctness_proof);
            unsafe {
                *signature_correctness_proof_p = Box::into_raw(Box::new(signature_correctness_proof)) as *const c_void;
                trace!("cl_signature_correctness_proof_from_json: *signature_correctness_proof_p: {:?}", *signature_correctness_proof_p);
            }
            ErrorCode::Success
        }
        Err(_) => ErrorCode::CommonInvalidStructure
    };

    trace!("cl_signature_correctness_proof_from_json: <<< res: {:?}", res);
    res
}

/// Deallocates signature correctness proof instance.
///
/// # Arguments
/// * `signature_correctness_proof` - Reference that contains signature correctness proof instance pointer.
#[no_mangle]
pub extern fn cl_signature_correctness_proof_free(signature_correctness_proof: *const c_void) -> ErrorCode {
    trace!("cl_signature_correctness_proof_free: >>> signature_correctness_proof: {:?}", signature_correctness_proof);

    check_useful_c_ptr!(signature_correctness_proof, ErrorCode::CommonInvalidParam1);

    let signature_correctness_proof = unsafe { Box::from_raw(signature_correctness_proof as *mut SignatureCorrectnessProof); };
    trace!("cl_signature_correctness_proof_free: entity: signature_correctness_proof: {:?}", signature_correctness_proof);
    let res = ErrorCode::Success;

    trace!("cl_signature_correctness_proof_free: <<< res: {:?}", res);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ptr;
    use ffi::cl::mocks::*;
    use ffi::cl::issuer::mocks::*;
    use ffi::cl::prover::mocks::*;

    #[test]
    fn cl_issuer_new_credential_def_works() {
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();
        let mut credential_pub_key: *const c_void = ptr::null();
        let mut credential_priv_key: *const c_void = ptr::null();
        let mut credential_key_correctness_proof: *const c_void = ptr::null();

        let err_code = cl_issuer_new_credential_def(credential_schema,
                                                                non_credential_schema,
                                                                &mut credential_pub_key,
                                                                &mut credential_priv_key,
                                                                &mut credential_key_correctness_proof);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_pub_key.is_null());
        assert!(!credential_priv_key.is_null());
        assert!(!credential_key_correctness_proof.is_null());

        _free_credential_schema(credential_schema);
        _free_non_credential_schema(non_credential_schema);
        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
    }

    #[test]
    fn cl_credential_public_key_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();

        let mut credential_pub_key_json_p: *const c_char = ptr::null();
        let err_code = cl_credential_public_key_to_json(credential_pub_key, &mut credential_pub_key_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
    }

    #[test]
    fn cl_credential_public_key_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();

        let mut credential_pub_key_json_p: *const c_char = ptr::null();
        let err_code = cl_credential_public_key_to_json(credential_pub_key, &mut credential_pub_key_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_pub_key_p: *const c_void = ptr::null();
        let err_code = cl_credential_public_key_from_json(credential_pub_key_json_p, &mut credential_pub_key_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
    }

    #[test]
    fn cl_credential_private_key_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();

        let mut credential_priv_key_json_p: *const c_char = ptr::null();
        let err_code = cl_credential_private_key_to_json(credential_priv_key, &mut credential_priv_key_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
    }

    #[test]
    fn cl_credential_private_key_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();

        let mut credential_priv_key_json_p: *const c_char = ptr::null();
        let err_code = cl_credential_private_key_to_json(credential_priv_key, &mut credential_priv_key_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_priv_key_p: *const c_void = ptr::null();
        let err_code = cl_credential_private_key_from_json(credential_priv_key_json_p, &mut credential_priv_key_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
    }

    #[test]
    fn cl_credential_key_correctness_proof_to_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();

        let mut credential_key_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = cl_credential_key_correctness_proof_to_json(credential_key_correctness_proof, &mut credential_key_correctness_proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
    }

    #[test]
    fn cl_issuer_key_correctness_proof_from_json_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();

        let mut credential_key_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = cl_credential_key_correctness_proof_to_json(credential_key_correctness_proof, &mut credential_key_correctness_proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_key_correctness_proof_p: *const c_void = ptr::null();
        let err_code = cl_credential_key_correctness_proof_from_json(credential_key_correctness_proof_json_p,
                                                                                 &mut credential_key_correctness_proof_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
    }

    #[test]
    fn cl_credential_def_free_works() {
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();

        let err_code = cl_credential_public_key_free(credential_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = cl_credential_private_key_free(credential_priv_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = cl_credential_key_correctness_proof_free(credential_key_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);
    }
    #[test]
    fn cl_issuer_sign_credential_works() {
        let prover_id = _prover_did();
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
        let credential_nonce = _nonce();
        let credential_issuance_nonce = _nonce();
        let (blinded_credential_secrets, credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof) = _blinded_credential_secrets(credential_pub_key,
                                                                                   credential_key_correctness_proof,
                                                                                   credential_values,
                                                                                   credential_nonce);

        let mut credential_signature_p: *const c_void = ptr::null();
        let mut credential_signature_correctness_proof_p: *const c_void = ptr::null();
        let err_code = cl_issuer_sign_credential(prover_id.as_ptr(),
                                                             blinded_credential_secrets,
                                                             blinded_credential_secrets_correctness_proof,
                                                             credential_nonce,
                                                             credential_issuance_nonce,
                                                             credential_values,
                                                             credential_pub_key,
                                                             credential_priv_key,
                                                             &mut credential_signature_p,
                                                             &mut credential_signature_correctness_proof_p);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_signature_p.is_null());
        assert!(!credential_signature_correctness_proof_p.is_null());

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(credential_signature_p, credential_signature_correctness_proof_p);
    }

    #[test]
    fn cl_credential_signature_to_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
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


        let mut credential_signature_json_p: *const c_char = ptr::null();
        let err_code = cl_credential_signature_to_json(credential_signature, &mut credential_signature_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn cl_credential_signature_from_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
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


        let mut credential_signature_json_p: *const c_char = ptr::null();
        let err_code = cl_credential_signature_to_json(credential_signature, &mut credential_signature_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut credential_signature_p: *const c_void = ptr::null();
        let err_code = cl_credential_signature_from_json(credential_signature_json_p, &mut credential_signature_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn cl_signature_correctness_proof_to_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
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

        let mut signature_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = cl_signature_correctness_proof_to_json(signature_correctness_proof,
                                                                          &mut signature_correctness_proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn cl_signature_correctness_proof_from_json_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
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

        let mut signature_correctness_proof_json_p: *const c_char = ptr::null();
        let err_code = cl_signature_correctness_proof_to_json(signature_correctness_proof,
                                                                          &mut signature_correctness_proof_json_p);
        assert_eq!(err_code, ErrorCode::Success);

        let mut signature_correctness_proof_p: *const c_void = ptr::null();
        let err_code = cl_signature_correctness_proof_from_json(signature_correctness_proof_json_p,
                                                                            &mut signature_correctness_proof_p);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
        _free_credential_signature(credential_signature, signature_correctness_proof);
    }

    #[test]
    fn cl_credential_signature_free_works() {
        let credential_values = _credential_values();
        let (credential_pub_key, credential_priv_key, credential_key_correctness_proof) = _credential_def();
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
        let err_code = cl_credential_signature_free(credential_signature);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = cl_signature_correctness_proof_free(signature_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);

        _free_credential_def(credential_pub_key, credential_priv_key, credential_key_correctness_proof);
        _free_credential_values(credential_values);
        _free_blinded_credential_secrets(blinded_credential_secrets, credential_secrets_blinding_factors, blinded_credential_secrets_correctness_proof);
        _free_nonce(credential_nonce);
        _free_nonce(credential_issuance_nonce);
    }
}

pub mod mocks {
    use super::*;

    use std::ffi::CString;
    use std::ptr;
    use ffi::cl::mocks::*;

    pub fn _credential_def() -> (*const c_void, *const c_void, *const c_void) {
        let credential_schema = _credential_schema();
        let non_credential_schema = _non_credential_schema();

        let mut credential_pub_key: *const c_void = ptr::null();
        let mut credential_priv_key: *const c_void = ptr::null();
        let mut credential_key_correctness_proof: *const c_void = ptr::null();

        let err_code = cl_issuer_new_credential_def(credential_schema,
                                                                non_credential_schema,
                                                                &mut credential_pub_key,
                                                                &mut credential_priv_key,
                                                                &mut credential_key_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_pub_key.is_null());
        assert!(!credential_priv_key.is_null());
        assert!(!credential_key_correctness_proof.is_null());

        _free_credential_schema(credential_schema);
        _free_non_credential_schema(non_credential_schema);

        (credential_pub_key, credential_priv_key, credential_key_correctness_proof)
    }

    pub fn _free_credential_def(credential_pub_key: *const c_void, credential_priv_key: *const c_void, credential_key_correctness_proof: *const c_void) {
        let err_code = cl_credential_public_key_free(credential_pub_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = cl_credential_private_key_free(credential_priv_key);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = cl_credential_key_correctness_proof_free(credential_key_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _credential_signature(blinded_credential_secrets: *const c_void, blinded_credential_secrets_correctness_proof: *const c_void,
                                 credential_nonce: *const c_void, credential_issuance_nonce: *const c_void, credential_values: *const c_void, credential_pub_key: *const c_void,
                                 credential_priv_key: *const c_void) -> (*const c_void, *const c_void) {
        let prover_id = _prover_did();

        let mut credential_signature_p: *const c_void = ptr::null();
        let mut credential_signature_correctness_proof_p: *const c_void = ptr::null();
        let err_code = cl_issuer_sign_credential(prover_id.as_ptr(),
                                                             blinded_credential_secrets,
                                                             blinded_credential_secrets_correctness_proof,
                                                             credential_nonce,
                                                             credential_issuance_nonce,
                                                             credential_values,
                                                             credential_pub_key,
                                                             credential_priv_key,
                                                             &mut credential_signature_p,
                                                             &mut credential_signature_correctness_proof_p);

        assert_eq!(err_code, ErrorCode::Success);
        assert!(!credential_signature_p.is_null());
        assert!(!credential_signature_correctness_proof_p.is_null());

    //        _free_credential_values(credential_values);

        (credential_signature_p, credential_signature_correctness_proof_p)
    }

    pub fn _free_credential_signature(credential_signature: *const c_void, signature_correctness_proof: *const c_void) {
        let err_code = cl_credential_signature_free(credential_signature);
        assert_eq!(err_code, ErrorCode::Success);

        let err_code = cl_signature_correctness_proof_free(signature_correctness_proof);
        assert_eq!(err_code, ErrorCode::Success);
    }

    pub fn _prover_did() -> CString {
        CString::new("CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW").unwrap()
    }
}