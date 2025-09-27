use hmac::{
    digest::{generic_array::GenericArray, OutputSizeUser},
    Mac,
};
use sha2::Digest;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};
use tpm2_rs_base::{
    commands::{
        CreatePrimaryCmd, StartAuthSessionCmd, StartAuthSessionHandles, StartAuthSessionResp,
        TpmCommand,
    },
    constants::{TpmCc, TpmSe},
    errors::{TssResult, TssTcsError},
    PublicParmsAndId, Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce,
    Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bSimple, Tpm2bStruct, TpmaObject,
    TpmaSession, TpmiAlgHash, TpmiDhEntity, TpmiDhObject, TpmiRhHierarchy, TpmiShAuthSession,
    TpmlPcrSelection, TpmsAuthCommand, TpmsAuthResponse, TpmsEmpty, TpmsKeyedHashParms,
    TpmsSchemeHash, TpmsSensitiveCreate, TpmtKeyedHashScheme, TpmtPublic,
};
use tpm2_rs_errors::TpmRcResult;
use tpm2_rs_marshalable::{Marshalable, UnmarshalBuf};

use crate::{run_command_with_handles, RespHeader, Session, Tpm};

#[test]
pub fn test_start_auth_create_primary() {
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

    let mut session = HmacSession::<AlgoSha256>::new(
        session_handle,
        nonce_caller,
        resp.nonce_tpm,
        TpmaSession::CONTINUE_SESSION,
    );

    // ### Execute `TPM2_CreatePrimary` command!
    let cmd_handle = TpmiRhHierarchy::TpmRhOwner;
    let (resp, handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();

    let (resp, handle) =
        run_command_with_handles(&cmd, &cmd_handle, &mut session, &mut tpm).unwrap();
}

// A simple file Io protocol.
struct FileIoTpm(std::fs::File);

impl FileIoTpm {
    fn new<P>(path: P) -> Result<Self, std::io::Error>
    where
        P: AsRef<Path>,
    {
        let f = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self(f))
    }
}

impl Tpm for FileIoTpm {
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TssResult<()> {
        const HEADER_SIZE: usize = 10;

        // Write command and flush.
        self.0.write_all(command).unwrap();
        self.0.flush().unwrap();

        // Create a temporary buffer such that an unexpected error later on does
        // result with parially written data in the response buffer.
        let mut header_bytes = [0u8; HEADER_SIZE];

        // Read the full response header.
        self.0.read_exact(&mut header_bytes).unwrap();

        // Unmarshal the response header.
        let mut unmarsh = UnmarshalBuf::new(&mut header_bytes);
        let header = RespHeader::try_unmarshal(&mut unmarsh)?;
        let resp_size = header.size as usize;

        // Copy header to response buffer.
        response[..HEADER_SIZE].copy_from_slice(&header_bytes);

        if resp_size > 10 {
            // Read the full remaining bytes.
            self.0
                .read_exact(&mut response[HEADER_SIZE..resp_size])
                .unwrap();
        }

        Ok(())
    }
}

pub trait AlgoDigest {
    type Hasher: AlgoDigestHasher;
    type Hmac: AlgoDigestHmac;
}

pub trait AlgoDigestHasher {
    type Output: AsRef<[u8]>;

    fn new() -> Self;
    fn output_size() -> usize;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;
}

pub trait AlgoDigestHmac {
    type Output: AsRef<[u8]>;

    fn new(key: &[u8]) -> Self;
    fn output_size() -> usize;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;
}

pub struct AlgoSha256;

impl AlgoDigest for AlgoSha256 {
    type Hmac = AlgoSha256Hmac;
    type Hasher = AlgoSha256Hasher;
}

pub struct AlgoSha256Hasher(sha2::Sha256);

impl AlgoDigestHasher for AlgoSha256Hasher {
    type Output = [u8; 32];

    fn new() -> Self {
        AlgoSha256Hasher(sha2::Sha256::new())
    }
    fn output_size() -> usize {
        32
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> Self::Output {
        self.0.finalize().into()
    }
}

pub struct AlgoSha256Hmac(hmac::Hmac<sha2::Sha256>);

impl AlgoDigestHmac for AlgoSha256Hmac {
    type Output = [u8; 32];

    fn new(key: &[u8]) -> Self {
        // TODO: Unwrap
        AlgoSha256Hmac(hmac::Hmac::new_from_slice(key).unwrap())
    }
    fn output_size() -> usize {
        32
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> Self::Output {
        self.0.finalize().into_bytes().into()
    }
}

/// Spec: 9.4.10.2 KDFa()
fn kdfa<M>(key: &[u8], label: &[u8], context: &[u8]) -> TssResult<Vec<u8>>
where
    M: AlgoDigestHmac,
{
    let mut buffer = Vec::with_capacity(M::output_size());
    let mut counter = 1u32;

    let bits = M::output_size() * 8;

    // TODO: This is kind of weird.
    while buffer.len() < (bits + 7) / 8 {
        let mut mac = M::new(key);

        mac.update(&counter.to_be_bytes());
        mac.update(label);
        if label.is_empty() || label.last().expect("TODO") != &0 {
            // > is added only if Label is not present or if the last octet of Label
            // > is not zero.
            mac.update(&[0x00]);
        }
        mac.update(context);
        mac.update(&(bits as u32).to_be_bytes());

        // > After each iteration, the HMAC digest data is concatenated to the
        // > previously produced value until the size of the concatenated string is
        // > at least as large as the requested value. The string is then truncated
        // > to the desired size (which causes the loss of some of the most recently
        // > added bits), and the value is returned.
        // TODO: Call `finalize_reset()`?
        buffer.extend_from_slice(mac.finalize().as_ref());

        counter += 1;
    }

    buffer.truncate((bits + 7) / 8);
    Ok(buffer)
}

pub fn session_key_v2<M>(
    auth_val: &[u8],
    salt: &[u8],
    nonce_tpm: &Tpm2bNonce,
    nonce_caller: &Tpm2bNonce,
) -> TssResult<Vec<u8>>
where
    M: AlgoDigestHmac,
{
    let key = [auth_val, salt].concat();
    let context = [nonce_tpm.get_buffer(), nonce_caller.get_buffer()].concat();

    let buffer = kdfa::<M>(&key, b"ATH", &context)?;
    Ok(buffer)
}

/// Spec: 16.7 Command Parameter Hash
/// > The command parameter hash (cpHash) is used in the computation of a
/// > command authorization HMAC and is included in the digests of session and
/// > command audits (depending on the policy, the cpHash can also be used in
/// > the authorization).
pub fn cp_hash<CmdT: TpmCommand, H: AlgoDigestHasher>(
    cmd: &CmdT,
    cmd_handles: &CmdT::Handles,
    buf: &mut [u8],
) -> TpmRcResult<H::Output> {
    let mut hash = H::new();

    let n = CmdT::CMD_CODE.try_marshal(buf)?;
    hash.update(&buf[..n]);

    let n = cmd_handles.try_marshal(buf)?;
    hash.update(&buf[..n]);

    let n = cmd.try_marshal(buf)?;
    hash.update(&buf[..n]);

    Ok(hash.finalize())
}

/// Spec: 16.8 Response Parameter Hash
/// > The response parameter hash (rpHash) is used in the computation of a
/// > response acknowledgment HMAC and is included in the digest of session and
/// > command audits.
pub fn rp_hash<CmdT: TpmCommand, H: AlgoDigestHasher>(
    resp: &CmdT::RespT,
    buf: &mut [u8],
) -> TpmRcResult<H::Output> {
    let mut hash = H::new();

    // Response code of `TPM_RC_SUCCESS = 0`.
    //
    // > An rpHash needs to be computed only when the responseCode is
    // > TPM_SUCCESS, which means that it is redundant to include the response
    // > code. It is retained for legacy reasons.
    let n = 0u32.try_marshal(buf)?;
    hash.update(&buf[..n]);

    let n = CmdT::CMD_CODE.try_marshal(buf)?;
    hash.update(&buf[..n]);

    let n = resp.try_marshal(buf)?;
    hash.update(&buf[..n]);

    Ok(hash.finalize())
}

/// Spec: 17.6.5 HMAC Computation
/// > The HMAC computation for all session types is the same. A sessionKey value
/// > is concatenated to an authValue to create the key that is used in the
/// > computation of the HMAC in a command or response.
//
// TODO:
// > If sessionKey and End of Example authvalue are both the Empty Buffer,
// > see Clause 17.6.15.
pub fn hmac_computation<M>(
    auth_val: &[u8],
    session_key: &[u8],
    p_hash: &[u8],
    nonce_newer: &Tpm2bNonce,
    nonce_older: &Tpm2bNonce,
    session_attributes: &TpmaSession,
) -> TpmRcResult<Tpm2bDigest>
where
    M: AlgoDigestHmac,
{
    let mut buf = vec![0u8; 1_024];

    let n0 = session_key.len();
    let n1 = auth_val.len();

    buf[00..n0 + 00].copy_from_slice(session_key);
    buf[n0..n0 + n1].copy_from_slice(auth_val);

    let key = &buf[..n0 + n1];
    let mut mac = M::new(key);

    mac.update(p_hash);

    let n = nonce_newer.try_marshal(&mut buf)?;
    mac.update(&buf[2..n]); // NOTE: excluding size indicator!

    let n = nonce_older.try_marshal(&mut buf)?;
    mac.update(&buf[2..n]); // NOTE: excluding size indicator!

    let n = session_attributes.try_marshal(&mut buf)?;
    mac.update(&buf[..n]);

    Tpm2bDigest::from_bytes(&mac.finalize().as_ref())
}

// A simple Hmac session (TODO: this should probably do some extra work).
pub struct HmacSession<D> {
    // TODO: const size should be standardized?
    buf: [u8; 1_024],
    session_handle: TpmiShAuthSession,
    nonce_caller: Tpm2bDigest,
    nonce_tpm: Tpm2bNonce,
    og_nonce_caller: Tpm2bDigest,
    og_nonce_tpm: Tpm2bNonce,
    session_attributes: TpmaSession,
    _p: std::marker::PhantomData<D>,
}

impl<D> HmacSession<D> {
    pub fn new(
        session_handle: TpmiShAuthSession,
        nonce_caller: Tpm2bNonce,
        nonce_tpm: Tpm2bNonce,
        session_attributes: TpmaSession,
    ) -> Self {
        Self {
            buf: [0u8; 1_024],
            session_handle,
            nonce_caller: Tpm2bDigest::default(),
            nonce_tpm,
            og_nonce_caller: nonce_caller,
            og_nonce_tpm: nonce_tpm,
            session_attributes,
            _p: std::marker::PhantomData,
        }
    }
}

impl<D> Session for HmacSession<D>
where
    D: AlgoDigest,
{
    fn get_auth_command<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        cmd_handles: &CmdT::Handles,
    ) -> TpmsAuthCommand {
        // TODO:
        // > The minimum size for nonceCaller in TPM2_StartAuthSession() is 16
        // octets.
        // > The maximum size that may be requested for nonceTPM is the size of
        // the digest produced by the authorization session hash. Example: For
        // SHA-1, the maximum size for nonceTPM is 20 octets and for SHA256 it
        // is 32 octets.
        let r: [u8; 32] = rand::random();
        self.nonce_caller = Tpm2bDigest::from_bytes(&r).expect("nonce size must be valid");

        let cp_hash = cp_hash::<CmdT, D::Hasher>(cmd, cmd_handles, &mut self.buf).unwrap();

        let auth_val = &[];
        let session_key =
            session_key_v2::<D::Hmac>(auth_val, b"", &self.og_nonce_tpm, &self.og_nonce_caller)
                .unwrap();

        let hmac = hmac_computation::<D::Hmac>(
            auth_val,
            &session_key,
            cp_hash.as_ref(),
            &self.nonce_caller,
            &self.nonce_tpm,
            &self.session_attributes,
        )
        .unwrap();

        TpmsAuthCommand {
            session_handle: self.session_handle,
            nonce: self.nonce_caller,
            session_attributes: self.session_attributes,
            hmac,
        }
    }
    fn validate_auth_response<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        // TODO: Do something with that? Validate it?
        resp_handles: &CmdT::RespHandles,
        auth: &TpmsAuthResponse,
    ) -> TssResult<()> {
        // TODO:
        assert_eq!(D::Hasher::output_size(), D::Hmac::output_size());

        // TODO: Do those sizes have to match EXACTLY? Afaik 16bytes minimum,
        // and `output_size()` max.
        if auth.nonce.get_size() as usize != D::Hasher::output_size()
            || auth.session_attributes != self.session_attributes
            || auth.hmac.get_size() as usize != D::Hmac::output_size()
        {
            return Err(TssTcsError::BadParameter.into());
        }

        let rp_hash = rp_hash::<CmdT, D::Hasher>(resp, &mut self.buf)?;

        let auth_val = &[];
        let session_key =
            session_key_v2::<D::Hmac>(auth_val, b"", &self.og_nonce_tpm, &self.og_nonce_caller)
                .unwrap();

        let computed_hmac = hmac_computation::<D::Hmac>(
            auth_val,
            &session_key,
            rp_hash.as_ref(),
            &auth.nonce,
            &self.nonce_caller,
            &self.session_attributes,
        )
        .unwrap();

        // TODO: Make this nicer.
        let computed_hmac = Tpm2bData::from_bytes(&computed_hmac.get_buffer()[..32]).unwrap();

        if auth.hmac != computed_hmac {
            // TODO: Change error variant?
            return Err(TssTcsError::BadParameter.into());
        }

        // Update the TPM's nonce, which MUST be used on the next authorized
        // command.
        self.nonce_tpm = auth.nonce;

        Ok(())

        /* TODO: From Part1:
        17.6.3 Session Nonces
        17.6.3.1 Overview
        The primary use of a nonce in a session is to prevent an authorization from being reused. When the session
        is started by TPM2_StartAuthSession(), the caller indicates, among other things, the size of the nonces
        to be used in the authorization HMAC and an initial nonce value (nonceCaller). After establishing the session,
        the TPM returns a handle to identify the session and a TPM-generated random nonce (nonceTPM). The TPM
        stores this nonceTPM in the context of the session.
        Each time the session is used for authorization, the caller performs an HMAC using, along with other
        parameters, the last nonceTPM for the session and a new nonceCaller for the session. The TPM then uses the
        received nonceCaller and the saved nonceTPM to validate the HMAC. For a response, the TPM uses the last
        nonceCaller and a newly generated nonceTPM in the HMAC. The caller then uses the received nonceTPM and
        the saved nonceCaller to validate the HMAC in the response.
        A nonce has a size field indicating the number of octets in the nonce followed by the nonce data. The nonce
        size is not included in the HMAC computation.


        16.8 Response Parameter Hash
        The response parameter hash (rpHash) is used in the computation of a response acknowledgment HMAC and
        is included in the digest of session and command audits. The rpHash is computed from the parameters of the
        response as follows:
        rpHash ∶= HsessionAlg (responseCode ∥ commandCode {∥ parameters })
        (16)
        where
        HsessionAlgis the hash function using the algorithm selected
        for the session when it was initialized
        responseCodeis the command result code
        commandCodeis the commandCode from the command
        parametersis the response parameters
        The contents of the handles area of the response are not included in the rpHash.
        An rpHash needs to be computed only when the responseCode is TPM_SUCCESS, which means that it is
        redundant to include the response code. It is retained for legacy reasons.
                */
    }
}
