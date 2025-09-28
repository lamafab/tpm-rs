use crate::{
    algo::{AlgoDigest, AlgoDigestHasher, AlgoDigestHmac},
    crypto::{cp_hash, hmac_computation, rp_hash, session_key},
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
        buf: &mut [u8],
    ) -> TpmsAuthCommand;
    /// Validates the authorization response for this session.
    fn validate_auth_response<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        resp_handles: &CmdT::RespHandles,
        auth: &TpmsAuthResponse,
        buf: &mut [u8],
    ) -> TssResult<()>;
}

// A simple Hmac session.
pub struct HmacSession<D>
where
    D: AlgoDigest,
{
    session_handle: TpmiShAuthSession,
    session_attributes: TpmaSession,
    session_key: Option<<D::Hmac as AlgoDigestHmac>::Output>,
    nonce_caller: Tpm2bDigest,
    nonce_tpm: Tpm2bNonce,
    _p: std::marker::PhantomData<D>,
}

impl<D> HmacSession<D>
where
    D: AlgoDigest,
{
    pub fn new(
        session_handle: TpmiShAuthSession,
        session_attributes: TpmaSession,
        session_key: Option<<D::Hmac as AlgoDigestHmac>::Output>,
        nonce_tpm: Tpm2bNonce,
    ) -> Self {
        Self {
            session_handle,
            session_attributes,
            session_key,
            nonce_caller: Tpm2bDigest::default(),
            nonce_tpm,
            _p: std::marker::PhantomData,
        }
    }
}

impl<D> Session for HmacSession<D>
where
    D: AlgoDigest,
{
    /// Spec (Part 1): 17.6.3.1 Overview
    fn get_auth_command<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        cmd_handles: &CmdT::Handles,
        buf: &mut [u8],
    ) -> TpmsAuthCommand {
        // > The minimum size for nonceCaller in TPM2_StartAuthSession() is 16
        // > octets. The maximum size that may be requested for nonceTPM is the
        // > size of the digest produced by the authorization session hash.
        // > Example: For SHA-1, the maximum size for nonceTPM is 20 octets and
        // > for SHA256 it is 32 octets.
        let nonce_buf: [u8; 32] = rand::random();
        let nonce_buf = &nonce_buf[..D::Hasher::OUTPUT_SIZE];

        self.nonce_caller = Tpm2bDigest::from_bytes(&nonce_buf).expect("nonce size must be valid");

        let cp_hash = cp_hash::<CmdT, D::Hasher>(cmd, cmd_handles, buf).unwrap();

        let auth_val = &[];

        let session_key = self.session_key.as_ref().map(|k| k.as_ref()).unwrap_or(&[]);

        let computed_hmac = hmac_computation::<D::Hmac>(
            auth_val,
            &session_key,
            cp_hash.as_ref(),
            &self.nonce_caller,
            &self.nonce_tpm,
            &self.session_attributes,
            buf,
        )
        .unwrap();

        TpmsAuthCommand {
            session_handle: self.session_handle,
            nonce: self.nonce_caller,
            session_attributes: self.session_attributes,
            hmac: computed_hmac,
        }
    }
    /// Spec (Part 1): 16.8 Response Parameter Hash
    fn validate_auth_response<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        // TODO: Do something with that? Validate it?
        resp_handles: &CmdT::RespHandles,
        auth: &TpmsAuthResponse,
        buf: &mut [u8],
    ) -> TssResult<()> {
        // TODO: Do those sizes have to match EXACTLY? Afaik 16bytes minimum,
        // and `output_size()` max.
        if auth.nonce.get_size() as usize != D::Hasher::OUTPUT_SIZE
            || auth.session_attributes != self.session_attributes
            || auth.hmac.get_size() as usize != D::Hmac::OUTPUT_SIZE
        {
            return Err(TssTcsError::BadParameter.into());
        }

        let rp_hash = rp_hash::<CmdT, D::Hasher>(resp, buf)?;

        let auth_val = &[];
        let session_key = self.session_key.as_ref().map(|k| k.as_ref()).unwrap_or(&[]);

        let computed_hmac = hmac_computation::<D::Hmac>(
            auth_val,
            &session_key,
            rp_hash.as_ref(),
            &auth.nonce,
            &self.nonce_caller,
            &self.session_attributes,
            buf,
        )
        .unwrap();

        if auth.hmac.get_buffer() != computed_hmac.get_buffer() {
            // TODO: Change error variant?
            return Err(TssTcsError::BadParameter.into());
        }

        // Update the TPM's nonce, which MUST be used on the next authorized
        // command.
        self.nonce_tpm = auth.nonce;

        Ok(())
    }
}
