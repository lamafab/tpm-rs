use crate::{
    algo::{AlgoDigest, AlgoDigestHasher, AlgoDigestHmac},
    crypto::{cp_hash, hmac_computation, rp_hash, session_key_v2},
};
use tpm2_rs_base::{
    commands::TpmCommand, Tpm2bData, Tpm2bDigest, Tpm2bNonce, Tpm2bSimple, TpmaSession,
    TpmiShAuthSession, TpmsAuthCommand, TpmsAuthResponse,
};
use tpm2_rs_errors::{TssResult, TssTcsError};

/// Trait for types representing TPM sessions.
pub trait Session {
    /// Computes the authorization HMAC for this session.
    fn get_auth_command<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        cmd_handles: &CmdT::Handles,
    ) -> TpmsAuthCommand;
    /// Validates the authorization response for this session.
    fn validate_auth_response<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        resp_handles: &CmdT::RespHandles,
        auth: &TpmsAuthResponse,
    ) -> TssResult<()>;
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
