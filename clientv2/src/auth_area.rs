use tpm2_rs_base::{commands::TpmCommand, TpmsAuthResponse};
use tpm2_rs_errors::{TssResult, TssTcsError};
use tpm2_rs_marshalable::{Marshalable, UnmarshalBuf};

use crate::session::Session;

// TODO: Define CmdT at top level?
pub trait AuthorizationArea {
    fn has_sessions(&self) -> bool;
    fn write_session_data<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        handles: &CmdT::Handles,
        buf: &mut [u8],
    ) -> TssResult<usize>;
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        // TODO: This needed?
        resp_handles: &CmdT::RespHandles,
        unmarsh: &mut UnmarshalBuf,
        wrk_buf: &mut [u8],
    ) -> TssResult<()>;
}

/// Empty session.
impl AuthorizationArea for () {
    fn has_sessions(&self) -> bool {
        false
    }
    fn write_session_data<CmdT: TpmCommand>(
        &mut self,
        _cmd: &CmdT,
        _handles: &CmdT::Handles,
        _buf: &mut [u8],
    ) -> TssResult<usize> {
        // TODO: Good error variant?
        TssResult::Err(TssTcsError::Unsupported.into())
    }
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        _resp: &CmdT::RespT,
        _resp_handles: &CmdT::RespHandles,
        _unmarsh: &mut UnmarshalBuf,
        _wrk_buf: &mut [u8],
    ) -> TssResult<()> {
        // TODO: Good error variant?
        TssResult::Err(TssTcsError::Unsupported.into())
    }
}

impl<T: Session> AuthorizationArea for T {
    fn has_sessions(&self) -> bool {
        true
    }
    fn write_session_data<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        handles: &CmdT::Handles,
        buf: &mut [u8],
    ) -> TssResult<usize> {
        // The length of the authorization area size indicator.
        const SIZE_LEN: usize = 4;

        if buf.len() < SIZE_LEN {
            return TssResult::Err(TssTcsError::OutOfMemory.into());
        }

        // Marshal the authorization area _after_ its reserved size indicator.
        let n = self
            .get_auth_command(cmd, handles, buf)
            .try_marshal(&mut buf[SIZE_LEN..])?;

        // Marshal the size indicator _before_ the authorization area.
        (n as u32).try_marshal(&mut buf[..SIZE_LEN])?;

        Ok(SIZE_LEN + n)
    }
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        resp_handles: &CmdT::RespHandles,
        unmarsh: &mut UnmarshalBuf,
        wrk_buf: &mut [u8],
    ) -> TssResult<()> {
        let auth = TpmsAuthResponse::try_unmarshal(unmarsh)?;
        self.validate_auth_response::<CmdT>(resp, resp_handles, &auth, wrk_buf)?;

        Ok(())
    }
}

impl<T: Session> AuthorizationArea for [T; 1] {
    fn has_sessions(&self) -> bool {
        self[0].has_sessions()
    }
    fn write_session_data<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        handles: &CmdT::Handles,
        buf: &mut [u8],
    ) -> TssResult<usize> {
        self[0].write_session_data(cmd, handles, buf)
    }
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        resp_handles: &CmdT::RespHandles,
        unmarsh: &mut UnmarshalBuf,
        wrk_buf: &mut [u8],
    ) -> TssResult<()> {
        self[0].read_response_data::<CmdT>(resp, resp_handles, unmarsh, wrk_buf)
    }
}

impl<T: Session> AuthorizationArea for [T; 2] {
    fn has_sessions(&self) -> bool {
        self.iter().any(|t| t.has_sessions())
    }
    fn write_session_data<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        handles: &CmdT::Handles,
        buf: &mut [u8],
    ) -> TssResult<usize> {
        let mut n = 0;
        n += self[0].write_session_data(cmd, handles, &mut buf[n..])?;
        n += self[1].write_session_data(cmd, handles, &mut buf[n..])?;
        Ok(n)
    }
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        resp_handles: &CmdT::RespHandles,
        unmarsh: &mut UnmarshalBuf,
        wrk_buf: &mut [u8],
    ) -> TssResult<()> {
        self[0].read_response_data::<CmdT>(resp, resp_handles, unmarsh, wrk_buf)?;
        self[1].read_response_data::<CmdT>(resp, resp_handles, unmarsh, wrk_buf)
    }
}

impl<T: Session> AuthorizationArea for [T; 3] {
    fn has_sessions(&self) -> bool {
        self.iter().any(|t| t.has_sessions())
    }
    fn write_session_data<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        handles: &CmdT::Handles,
        buf: &mut [u8],
    ) -> TssResult<usize> {
        let mut n = 0;
        n += self[0].write_session_data(cmd, handles, &mut buf[n..])?;
        n += self[1].write_session_data(cmd, handles, &mut buf[n..])?;
        n += self[2].write_session_data(cmd, handles, &mut buf[n..])?;
        Ok(n)
    }
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        resp_handles: &CmdT::RespHandles,
        unmarsh: &mut UnmarshalBuf,
        wrk_buf: &mut [u8],
    ) -> TssResult<()> {
        self[0].read_response_data::<CmdT>(resp, resp_handles, unmarsh, wrk_buf)?;
        self[1].read_response_data::<CmdT>(resp, resp_handles, unmarsh, wrk_buf)?;
        self[2].read_response_data::<CmdT>(resp, resp_handles, unmarsh, wrk_buf)
    }
}
