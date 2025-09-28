use std::fs;

use crate::{
    algo::{AlgoSha256, AlgoSha256Hmac},
    crypto::session_key,
    session::HmacSession,
    tpm::{run_command_with_handles, FileIoTpm},
};
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use tpm2_rs_base::{
    commands::{
        CreatePrimaryCmd, LoadCmd, LoadExternalCmd, ReadPublicCmd, StartAuthSessionCmd,
        StartAuthSessionHandles,
    },
    constants::TpmSe,
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bPublic, Tpm2bPublicKeyRsa, Tpm2bSensitive, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
    Tpm2bSimple, Tpm2bStruct, TpmaObject, TpmaSession, TpmiAlgHash, TpmiDhEntity, TpmiDhObject,
    TpmiRhHierarchy, TpmiRsaKeyBits, TpmlPcrSelection, TpmsEmpty, TpmsEncSchemeOaep,
    TpmsKeyedHashParms, TpmsRsaParms, TpmsSchemeHash, TpmsSensitiveCreate, TpmtKeyedHashScheme,
    TpmtPublic,
};

#[test]
fn test_start_auth_create_primary() {
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

    // ## Prepare payload for `TPM2_LoadExternal` command.
    
    /*
    let object_attributes = TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN
        | TpmaObject::USER_WITH_AUTH
        | TpmaObject::DECRYPT;

    // Use empty auth policy.
    let auth_policy = Tpm2bDigest::from_bytes(&[]).unwrap();

    let rsa_id = hex::decode("bbc7e82763862a98fc2e0c0d998ff77d976565b10d71c9a304c0426a28efeda3294d300e7475e111a96e392f60e57bf8c0b5f5363bbffad4864d05fce2bc43c3c41d1fd99ea4e314396ecb8deb3bbb526c65cefa81bb1d70c2015878f5a4238c398a2392779fa5843a7276a9a3ace9aa1c8d9e9293673f2f5b541ede88ef76d52e1b6fb5b8c73e0dfe33fcbba2b8e83bf3457071e9db88d6f68c08c4ffa2eedf3b5f432d12d1fe62ccd9a1404b7e2b323a0ca119efe3d82346fa1463cf46faf21ce8ab97b76b18dceea05d0fc31d89b39ad501ea900373279b850c7a82a32b0284fe42aae2acf2b2fec2ab89e8ad4b8a0b224325601d6bc0cfece763d72de543").unwrap();
    let parms_and_id = PublicParmsAndId::Rsa(
        TpmsRsaParms {
            symmetric: tpm2_rs_base::TpmtSymDefObject::Null(TpmsEmpty, TpmsEmpty),
            scheme: tpm2_rs_base::TpmtRsaScheme::Null(TpmsEmpty),
            /*
            scheme: tpm2_rs_base::TpmtRsaScheme::Oaep(TpmsEncSchemeOaep {
                hash_alg: TpmiAlgHash::SHA256,
            }),
            */
            key_bits: TpmiRsaKeyBits::Rsa2048,
            exponent: 65537,
        },
        Tpm2bPublicKeyRsa::from_bytes(&rsa_id).unwrap(),
    );

    let in_public = Tpm2bPublic::from_struct(&TpmtPublic {
        name_alg: TpmiAlgHash::SHA256,
        object_attributes,
        auth_policy,
        parms_and_id,
    })
    .unwrap();

    let cmd = LoadExternalCmd {
        in_private: Tpm2bSensitive::from_bytes(&[]).unwrap(),
        in_public,
        hierarchy: TpmiRhHierarchy::TpmRhOwner,
    };

    let mut cmd_session = ();
    let cmd_handles = ();

    // ### Execute `TPM2_LoadExternal` command!
    let (_resp, object_handle) =
        run_command_with_handles(&cmd, &cmd_handles, &mut cmd_session, &mut tpm).unwrap();
    */

    // ## Prepare payload for `TPM2_StartAuthSession` command.

    // Setup the TPM's RSA public key.
    let rsa_pem = fs::read_to_string("../ek_public.pem").unwrap();
    let rsa = RsaPublicKey::from_public_key_pem(&rsa_pem).unwrap();

    // Generate random nonce, use empty salt.
    let nonce_caller = Tpm2bNonce::from_bytes(&rand::random::<[u8; 32]>()).unwrap();

    let mut rng = rsa::rand_core::OsRng;
    let salt = rand::random::<[u8; 32]>();
    let padding = rsa::Oaep::new::<sha2::Sha256>();
    //let padding = rsa::Oaep::new_with_mgf_hash_and_label::<sha2::Sha256, sha2::Sha256, &str>("");
    let encrypted_salt = rsa.encrypt(&mut rng, padding, &salt).unwrap();

    let encrypted_salt = [];
    let encrypted_salt = Tpm2bEncryptedSecret::from_bytes(&encrypted_salt).unwrap();

    let cmd = StartAuthSessionCmd {
        nonce_caller,
        encrypted_salt,
        session_type: TpmSe::HMAC,
        symmetric: tpm2_rs_base::TpmtSymDefObject::Null(TpmsEmpty, TpmsEmpty),
        auth_hash: TpmiAlgHash::SHA256,
    };

    let cmd_handles = StartAuthSessionHandles {
        tpm_key: TpmiDhObject::RHNull,
        //tpm_key: TpmiDhObject(0x81000011),
        bind: TpmiDhEntity(0x81000011),
    };

    let mut cmd_session = ();

    // ### Execute `TPM2_StartAuthSession` command!
    let (resp, session_handle) =
        run_command_with_handles(&cmd, &cmd_handles, &mut cmd_session, &mut tpm).unwrap();

    return;

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
        session_key::<AlgoSha256Hmac>(&[], &salt, &resp.nonce_tpm, &nonce_caller).unwrap();

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
