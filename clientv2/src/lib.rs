use tpm2_rs_base::{
    commands::TpmCommand,
    constants::{TpmCc, TpmSt},
    errors::{TssError, TssResult, TssTcsError},
    TpmiStCommandTag, TpmsAuthCommand, TpmsAuthResponse,
};
use tpm2_rs_marshalable::{Marshalable, UnmarshalBuf};

pub mod session;

pub const CMD_BUFFER_SIZE: usize = 4096;
pub const RESP_BUFFER_SIZE: usize = 4096;

pub trait Tpm {
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TssResult<()>;
}

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

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct CmdHeader {
    tag: TpmiStCommandTag,
    size: u32,
    code: TpmCc,
}

impl CmdHeader {
    pub fn new(has_sessions: bool, code: TpmCc) -> CmdHeader {
        let tag = if has_sessions {
            TpmiStCommandTag::Sessions
        } else {
            TpmiStCommandTag::NoSessions
        };
        CmdHeader { tag, size: 0, code }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable, Debug)]
pub struct RespHeader {
    pub tag: TpmSt,
    pub size: u32,
    pub rc: u32,
}

impl RespHeader {
    const SIZE: usize = 10;
}

/// Umarshals the response header and checks the contained response code.
pub fn read_response_header(buffer: &[u8]) -> TssResult<(RespHeader, usize)> {
    let mut unmarsh = UnmarshalBuf::new(buffer);
    let resp_header = RespHeader::try_unmarshal(&mut unmarsh)?;
    if let Ok(error) = TssError::try_from(resp_header.rc) {
        return TssResult::Err(error);
    }
    Ok((resp_header, buffer.len() - unmarsh.len()))
}

/// Runs a command with provided handles and sessions.
pub fn run_command_with_handles<CmdT, TpmT, AA: AuthorizationArea>(
    cmd: &CmdT,
    cmd_handles: &CmdT::Handles,
    cmd_sessions: &mut AA,
    tpm: &mut TpmT,
) -> TssResult<(CmdT::RespT, CmdT::RespHandles)>
where
    CmdT: TpmCommand,
    TpmT: Tpm,
{
    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let mut cmd_header = CmdHeader::new(cmd_sessions.has_sessions(), CmdT::CMD_CODE);
    let mut written = cmd_header.try_marshal(&mut cmd_buffer)?;

    written += cmd_handles.try_marshal(&mut cmd_buffer[written..])?;
    written += cmd_sessions.write_session_data(cmd, cmd_handles, &mut cmd_buffer[written..])?;
    written += cmd.try_marshal(&mut cmd_buffer[written..])?;

    // Update the command size.
    cmd_header.size = written as u32;
    let _ = cmd_header.try_marshal(&mut cmd_buffer)?;

    // Write buffer to TPM and retrieve response.
    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    tpm.transact(&cmd_buffer[..written], &mut resp_buffer)?;

    // Unmarshal response header.
    let mut unmarsh = UnmarshalBuf::new(&resp_buffer);
    let resp_header = RespHeader::try_unmarshal(&mut unmarsh)?;
    if let Ok(error) = TssError::try_from(resp_header.rc) {
        return TssResult::Err(error);
    }

    // Check response size.
    let resp_size = resp_header.size as usize;
    if resp_size > resp_buffer.len() {
        return TssResult::Err(TssTcsError::OutOfMemory.into());
    }

    // Unmarshal response handles.
    let mut unmarsh = UnmarshalBuf::new(&resp_buffer[RespHeader::SIZE..resp_size]);
    let resp_handles = CmdT::RespHandles::try_unmarshal(&mut unmarsh)?;
    if resp_header.tag == TpmSt::Sessions {
        let _param_size = u32::try_unmarshal(&mut unmarsh)?;
    }

    // Unmarshal response parameters.
    let resp = CmdT::RespT::try_unmarshal(&mut unmarsh)?;
    cmd_sessions.read_response_data::<CmdT>(&resp, &resp_handles, &mut unmarsh)?;

    if !unmarsh.is_empty() {
        return TssResult::Err(TssTcsError::TpmUnexpected.into());
    }

    Ok((resp, resp_handles))
}

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
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()>;
}

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
        Ok(0)
    }
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        _resp: &CmdT::RespT,
        _resp_handles: &CmdT::RespHandles,
        _buf: &mut UnmarshalBuf,
    ) -> TssResult<()> {
        Ok(())
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
        const SIZE_LEN: usize = 4;

        if buf.len() < 4 {
            return TssResult::Err(TssTcsError::OutOfMemory.into());
        }

        let n = self
            .get_auth_command(cmd, handles)
            .try_marshal(&mut buf[SIZE_LEN..])?;

        (n as u32).try_marshal(&mut buf[..SIZE_LEN]).expect("TODO");

        Ok(SIZE_LEN + n)
    }
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        resp: &CmdT::RespT,
        resp_handles: &CmdT::RespHandles,
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()> {
        let auth = TpmsAuthResponse::try_unmarshal(buf)?;
        self.validate_auth_response::<CmdT>(resp, resp_handles, &auth)?;

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
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()> {
        self[0].read_response_data::<CmdT>(resp, resp_handles, buf)
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
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()> {
        self[0].read_response_data::<CmdT>(resp, resp_handles, buf)?;
        self[1].read_response_data::<CmdT>(resp, resp_handles, buf)
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
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()> {
        self[0].read_response_data::<CmdT>(resp, resp_handles, buf)?;
        self[1].read_response_data::<CmdT>(resp, resp_handles, buf)?;
        self[2].read_response_data::<CmdT>(resp, resp_handles, buf)
    }
}
