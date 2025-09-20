use tpm2_rs_base::{commands::TpmCommand, errors::TssResult, TpmsAuthCommand, TpmsAuthResponse};

/// Trait for types representing TPM sessions.
pub trait Session {
    /// Computes the authorization HMAC for this session.
    fn get_auth_command<CMD: TpmCommand>(
        &mut self,
        cmd: &CMD,
        cmd_handles: &CMD::Handles,
    ) -> TpmsAuthCommand;
    /// Validates the authorization response for this session.
    fn validate_auth_response(&mut self, auth: &TpmsAuthResponse) -> TssResult<()>;
}
