use crate::{
    algo::{AlgoSha256, AlgoSha256Hasher, AlgoSha256Hmac},
    crypto::session_key,
    session::HmacSession,
    tpm::{run_command_with_handles, FileIoTpm},
};
use tpm2_rs_base::{
    commands::{CreatePrimaryCmd, StartAuthSessionCmd, StartAuthSessionHandles},
    constants::TpmSe,
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bSimple, Tpm2bStruct, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiDhEntity, TpmiDhObject, TpmiRhHierarchy, TpmlPcrSelection,
    TpmsEmpty, TpmsKeyedHashParms, TpmsSchemeHash, TpmsSensitiveCreate, TpmtKeyedHashScheme,
    TpmtPublic,
};

#[test]
fn test_start_auth_create_primary() {
    // Use the specified TPM, with and empty auth key!
    let mut tpm = FileIoTpm::new("/dev/tpmrm0").unwrap();
    //let auth_key = [];

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
        session_handle,
        TpmaSession::CONTINUE_SESSION,
        Some(session_key),
        nonce_caller,
        resp.nonce_tpm,
    );

    // ### Execute `TPM2_CreatePrimary` command!
    let cmd_handle = TpmiRhHierarchy::TpmRhOwner;
    let (resp, handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();

    let (resp, handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();
}
