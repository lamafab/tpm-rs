use crate::sessions::Session;
use tpm2_rs_base::{commands::TpmCommand, errors::TssResult, TpmsAuthCommand, TpmsAuthResponse};

/// [`NoSession`] is not a standard TPM session and cannot be instantiated,
/// making it unsuitable for use as a session. Its primary purpose is to serve
/// as a placeholder type for the `AuthorizationArea*` traits whenever
/// necessary.
pub struct NoSession {
    #[expect(dead_code, reason = "This prevents having NotSession instances")]
    inaccessible: (),
}

impl Session for NoSession {
    fn get_auth_command<T: TpmCommand>(&mut self, _cmd: &T) -> TpmsAuthCommand {
        unreachable!()
    }
    fn validate_auth_response(&mut self, _: &TpmsAuthResponse) -> TssResult<()> {
        // unreachable macro may interfere with #42. If it does we can just
        // replace it with a loop {}.
        unreachable!()
    }
}
