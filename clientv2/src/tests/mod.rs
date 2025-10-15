use std::fs;

use crate::{
    algo::{AlgoSha256, AlgoSha256Hmac},
    crypto::session_key,
    session::{self, HmacSession, PasswordSession},
    tpm::{run_command_with_handles, FileIoTpm},
};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use tpm2_rs_base::{
    commands::{
        CreateCmd, CreatePrimaryCmd, LoadCmd, LoadExternalCmd, ReadPublicCmd, StartAuthSessionCmd,
        StartAuthSessionHandles, UnsealCmd,
    },
    constants::{TpmHandle, TpmHc, TpmSe},
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSensitive, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
    Tpm2bSimple, Tpm2bStruct, TpmaObject, TpmaSession, TpmiAlgHash, TpmiDhEntity, TpmiDhObject,
    TpmiRhHierarchy, TpmiRsaKeyBits, TpmlPcrSelection, TpmsEmpty, TpmsEncSchemeOaep,
    TpmsKeyedHashParms, TpmsRsaParms, TpmsSchemeHash, TpmsSensitiveCreate, TpmtKeyedHashScheme,
    TpmtPublic,
};
use tpm2_rs_marshalable::{Marshalable, UnmarshalBuf};

#[test]
fn test_start_auth_create_primary_simple() {
    // Use the specified TPM, with and empty auth key!
    let mut tpm = FileIoTpm::new("/dev/tpmrm0").unwrap();
    let auth_val = vec![];

    // ## Prepare payload for `TPM2_StartAuthSession`

    // Generate random nonce, use empty salt.
    let nonce_caller = Tpm2bNonce::from_bytes(&rand::random::<[u8; 32]>()).unwrap();
    // > If tpmKey Is TPM_RH_NULL, then encryptedSalt is required to be an Empty Buffer.
    let encrypted_salt = Tpm2bEncryptedSecret::from_bytes(b"").unwrap();

    let cmd = StartAuthSessionCmd {
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::HMAC,
        symmetric: tpm2_rs_base::TpmtSymDefObject::Null(TpmsEmpty, TpmsEmpty),
        auth_hash: TpmiAlgHash::SHA256,
    };

    let cmd_handles = StartAuthSessionHandles {
        tpm_key: TpmiDhObject::RHNull,
        bind: TpmiDhEntity::RHOwner,
    };

    let mut cmd_session = ();

    // ### Execute `TPM2_StartAuthSession` command!
    let (resp, session_handle) =
        run_command_with_handles(&cmd, &cmd_handles, &mut cmd_session, &mut tpm).unwrap();

    // ## Prepare payload for `TPM2_CreatePrimary`

    // Use empty auth, generate random sensitive data.
    let in_sensitive = Tpm2bSensitiveCreate::from_struct(&TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(&[]).unwrap(),
        // TODO: Note that if this is empty, object attribute must have `SENSITIVE_DATA_ORIGIN` set.
        data: Tpm2bSensitiveData::from_bytes(&rand::random::<[u8; 32]>()).unwrap(),
    })
    .unwrap();

    let object_attributes = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SIGN_ENCRYPT;

    // Use empty auth policy.
    let auth_policy = Tpm2bDigest::from_bytes(&[]).unwrap();

    let parms_and_id = PublicParmsAndId::KeyedHash(
        TpmsKeyedHashParms {
            scheme: TpmtKeyedHashScheme::Hmac(TpmsSchemeHash {
                hash_alg: TpmiAlgHash::SHA256,
            }),
        },
        Tpm2bDigest::from_bytes(&[]).unwrap(),
    );

    let in_public = Tpm2bPublic::from_struct(&TpmtPublic {
        name_alg: TpmiAlgHash::SHA256,
        object_attributes,
        auth_policy,
        parms_and_id,
    })
    .unwrap();

    // Use empty outside info, use empty creation PCR.
    let outside_info = Tpm2bData::from_bytes(&[]).unwrap();
    let creation_pcr = TpmlPcrSelection::new(&[]).unwrap();

    let cmd = CreatePrimaryCmd {
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let session_key =
        session_key::<AlgoSha256Hmac>(&[], &[], &resp.nonce_tpm, &nonce_caller).unwrap();

    let mut session = HmacSession::<AlgoSha256>::new(
        auth_val,
        session_handle,
        TpmaSession::CONTINUE_SESSION,
        Some(session_key),
        resp.nonce_tpm,
    );

    // ### Execute `TPM2_CreatePrimary` command!
    let cmd_handle = TpmiRhHierarchy::TpmRhOwner;
    let (resp, handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();

    let (resp, handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();
}

#[test]
fn test_start_auth_create_primary_with_rsa_encryption() {
    // Use the specified TPM, with and empty auth key!
    let mut tpm = FileIoTpm::new("/dev/tpmrm0").unwrap();
    let auth_val = vec![];

    // ## Prepare payload for `TPM2_StartAuthSession` command.

    // Setup the TPM's RSA public key.
    let rsa_pem = fs::read_to_string("../public.pem").unwrap();
    let rsa = RsaPublicKey::from_public_key_pem(&rsa_pem).unwrap();

    // Generate random nonce, use empty salt.
    let nonce_caller = Tpm2bNonce::from_bytes(&rand::random::<[u8; 32]>()).unwrap();

    let mut rng = rsa::rand_core::OsRng;
    let salt = rand::random::<[u8; 32]>();
    let padding =
        rsa::Oaep::new_with_mgf_hash_and_label::<sha2::Sha256, sha2::Sha256, &str>("SECRET\0"); // NOTE the null terminator!

    //let padding = rsa::Oaep::new_with_mgf_hash_and_label::<sha2::Sha256, sha2::Sha256, &str>("");
    let encrypted_salt = rsa.encrypt(&mut rng, padding, &salt).unwrap();

    assert_eq!(salt.len(), 32);
    assert_eq!(encrypted_salt.len(), 256);
    //
    let encrypted_salt = Tpm2bEncryptedSecret::from_bytes(&encrypted_salt).unwrap();

    let cmd = StartAuthSessionCmd {
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::HMAC,
        symmetric: tpm2_rs_base::TpmtSymDefObject::Null(TpmsEmpty, TpmsEmpty),
        auth_hash: TpmiAlgHash::SHA256,
    };

    let cmd_handles = StartAuthSessionHandles {
        tpm_key: TpmiDhObject(0x81000100),
        bind: TpmiDhEntity::RHOwner,
    };

    let mut cmd_session = ();

    // ### Execute `TPM2_StartAuthSession` command!
    let (resp, session_handle) =
        run_command_with_handles(&cmd, &cmd_handles, &mut cmd_session, &mut tpm).unwrap();

    // ## Prepare payload for `TPM2_CreatePrimary`

    let object_attributes = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SIGN_ENCRYPT;

    // Use empty auth policy.
    let auth_policy = Tpm2bDigest::from_bytes(&[]).unwrap();

    let parms_and_id = PublicParmsAndId::KeyedHash(
        TpmsKeyedHashParms {
            scheme: TpmtKeyedHashScheme::Hmac(TpmsSchemeHash {
                hash_alg: TpmiAlgHash::SHA256,
            }),
        },
        Tpm2bDigest::from_bytes(&[]).unwrap(),
    );

    let in_public = Tpm2bPublic::from_struct(&TpmtPublic {
        name_alg: TpmiAlgHash::SHA256,
        object_attributes,
        auth_policy,
        parms_and_id,
    })
    .unwrap();

    // Use empty auth, generate random sensitive data.
    let in_sensitive = Tpm2bSensitiveCreate::from_struct(&TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(&[]).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(&rand::random::<[u8; 32]>()).unwrap(),
    })
    .unwrap();

    // Use empty outside info, use empty creation PCR.
    let outside_info = Tpm2bData::from_bytes(&[]).unwrap();
    let creation_pcr = TpmlPcrSelection::new(&[]).unwrap();

    let cmd = CreatePrimaryCmd {
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let session_key =
        session_key::<AlgoSha256Hmac>(&auth_val, &salt, &resp.nonce_tpm, &nonce_caller).unwrap();

    let mut session = HmacSession::<AlgoSha256>::new(
        auth_val,
        session_handle,
        TpmaSession::CONTINUE_SESSION,
        Some(session_key),
        resp.nonce_tpm,
    );

    // ### Execute `TPM2_CreatePrimary` command!
    let cmd_handle = TpmiRhHierarchy::TpmRhOwner;
    let (resp, handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();

    dbg!(resp);
}

#[test]
fn test_start_auth_create_primary_with_unseal() {
    // Use the specified TPM, with and empty auth key!
    let mut tpm = FileIoTpm::new("/dev/tpmrm0").unwrap();
    let auth_val = [];
    let salt = [];

    // ## Prepare payload for `TPM2_StartAuthSession`

    // Generate random nonce, use empty salt.
    let nonce_caller = Tpm2bNonce::from_bytes(&rand::random::<[u8; 32]>()).unwrap();
    // > If tpmKey Is TPM_RH_NULL, then encryptedSalt is required to be an Empty Buffer.
    let encrypted_salt = Tpm2bEncryptedSecret::from_bytes(b"").unwrap();

    let cmd = StartAuthSessionCmd {
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::HMAC,
        symmetric: tpm2_rs_base::TpmtSymDefObject::Null(TpmsEmpty, TpmsEmpty),
        auth_hash: TpmiAlgHash::SHA256,
    };

    let cmd_handles = StartAuthSessionHandles {
        tpm_key: TpmiDhObject::RHNull,
        bind: TpmiDhEntity::RHOwner,
    };

    let mut cmd_session = ();

    // ### Execute `TPM2_StartAuthSession` command!
    let (resp, session_handle) =
        run_command_with_handles(&cmd, &cmd_handles, &mut cmd_session, &mut tpm).unwrap();

    let nonce_tpm = resp.nonce_tpm;

    // ## Prepare payload for `TPM2_CreatePrimary`

    let sensitive_data = rand::random::<[u8; 32]>();

    // Use empty auth, generate random sensitive data.
    let in_sensitive = Tpm2bSensitiveCreate::from_struct(&TpmsSensitiveCreate {
        user_auth: Tpm2bAuth::from_bytes(&[]).unwrap(),
        data: Tpm2bSensitiveData::from_bytes(&[]).unwrap(),
    })
    .unwrap();

    let object_attributes = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::SIGN_ENCRYPT
        //| TpmaObject::RESTRICTED
        | TpmaObject::SENSITIVE_DATA_ORIGIN;

    // Use empty auth policy.
    let auth_policy = Tpm2bDigest::from_bytes(&[]).unwrap();

    let parms_and_id = PublicParmsAndId::KeyedHash(
        TpmsKeyedHashParms {
            scheme: TpmtKeyedHashScheme::Hmac(TpmsSchemeHash {
                hash_alg: TpmiAlgHash::SHA256,
            }),
            //scheme: TpmtKeyedHashScheme::Null(TpmsEmpty),
        },
        Tpm2bDigest::from_bytes(&[]).unwrap(),
    );

    let in_public = Tpm2bPublic::from_struct(&TpmtPublic {
        name_alg: TpmiAlgHash::SHA256,
        object_attributes,
        auth_policy,
        parms_and_id,
    })
    .unwrap();

    // Use empty outside info, use empty creation PCR.
    let outside_info = Tpm2bData::from_bytes(&[]).unwrap();
    let creation_pcr = TpmlPcrSelection::new(&[]).unwrap();

    let cmd = CreatePrimaryCmd {
        in_sensitive,
        in_public,
        outside_info,
        creation_pcr,
    };

    let sess_key =
        session_key::<AlgoSha256Hmac>(&auth_val, &salt, &nonce_tpm, &nonce_caller).unwrap();

    let mut session = HmacSession::<AlgoSha256>::new(
        auth_val.to_vec(),
        session_handle,
        TpmaSession::CONTINUE_SESSION,
        Some(sess_key),
        nonce_tpm,
    );

    // ### Execute `TPM2_CreatePrimary` command!
    let cmd_handle = TpmiRhHierarchy::TpmRhOwner;
    let (resp, object_handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();

    return;

    assert!(TpmHc::is_transient_object(object_handle.0));

    let primary_name = resp.name;

    // #### NEW SESSION
    /*
    let nonce_caller = Tpm2bNonce::from_bytes(&rand::random::<[u8; 32]>()).unwrap();
    let encrypted_salt = Tpm2bEncryptedSecret::from_bytes(b"").unwrap();

    let cmd = StartAuthSessionCmd {
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::HMAC,
        symmetric: tpm2_rs_base::TpmtSymDefObject::Null(TpmsEmpty, TpmsEmpty),
        auth_hash: TpmiAlgHash::SHA256,
    };

    let cmd_handles = StartAuthSessionHandles {
        tpm_key: TpmiDhObject::RHNull,
        bind: TpmiDhEntity::RHNull,
    };

    let mut cmd_session = ();

    // ### Execute `TPM2_StartAuthSession` command!
    let (resp, session_handle) =
        run_command_with_handles(&cmd, &cmd_handles, &mut cmd_session, &mut tpm).unwrap();
    */

    let nonce_caller = Tpm2bNonce::from_bytes(&rand::random::<[u8; 32]>()).unwrap();

    let sess_key =
        session_key::<AlgoSha256Hmac>(&auth_val, &salt, &nonce_tpm, &nonce_caller).unwrap();

    let mut session = HmacSession::<AlgoSha256>::new(
        auth_val.to_vec(),
        session_handle,
        TpmaSession::CONTINUE_SESSION,
        Some(sess_key),
        nonce_tpm,
    );

    session.set_object_name(primary_name);

    // ### Execute `TPM2_Unseal` command!
    let cmd = UnsealCmd;
    let cmd_handle = TpmiDhObject(object_handle.0);

    let (resp, handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();

    assert_eq!(resp.out_data.get_buffer(), sensitive_data);
}

#[test]
fn test_create_save_context_unseal() {
    // Use the specified TPM, with and empty auth key!
    let mut tpm = FileIoTpm::new("/dev/tpmrm0").unwrap();

    let cmd = CreateCmd {};
}
