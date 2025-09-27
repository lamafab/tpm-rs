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
        cmd: &CmdT,
        resp: &CmdT::RespT,
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

/// This function serializes the size of the authorization area. `buffer` should
/// point to the beginning of the authorization area, specifically to the location
/// where the size of the authorization area will be serialized. The `auth_offset`
/// indicates the offset to the end of the authorization area. The size to be
/// serialized is calculated as the difference between the offset and the start
/// of the buffer, excluding the size of the integer used to store the size.
fn marshal_auth_size(auth_offset: usize, buffer: &mut [u8]) -> TssResult<usize> {
    let auth_size = (auth_offset - size_of::<u32>()) as u32;
    auth_size.try_marshal(buffer)?;
    Ok(auth_offset)
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
    // TODO: Maybe use `()` for no session?
    mut cmd_sessions: Option<&mut AA>,
    tpm: &mut TpmT,
) -> TssResult<(CmdT::RespT, CmdT::RespHandles)>
where
    CmdT: TpmCommand,
    TpmT: Tpm,
{
    let mut cmd_buffer = [0u8; CMD_BUFFER_SIZE];
    let mut cmd_header = CmdHeader::new(cmd_sessions.is_some(), CmdT::CMD_CODE);
    let mut written = cmd_header.try_marshal(&mut cmd_buffer)?;

    written += cmd_handles.try_marshal(&mut cmd_buffer[written..])?;
    if let Some(sessions) = cmd_sessions.as_mut() {
        written += sessions.write_session_data(cmd, cmd_handles, &mut cmd_buffer[written..])?;
    }
    written += cmd.try_marshal(&mut cmd_buffer[written..])?;

    // Update the command size
    cmd_header.size = written as u32;
    let _ = cmd_header.try_marshal(&mut cmd_buffer)?;

    let mut resp_buffer = [0u8; RESP_BUFFER_SIZE];
    tpm.transact(&cmd_buffer[..written], &mut resp_buffer)?;

    let (resp_header, read) = read_response_header(&resp_buffer)?;
    let resp_size = resp_header.size as usize;
    if resp_size > resp_buffer.len() {
        return TssResult::Err(TssTcsError::OutOfMemory.into());
    }
    let mut unmarsh = UnmarshalBuf::new(&resp_buffer[read..resp_size]);
    let resp_handles = CmdT::RespHandles::try_unmarshal(&mut unmarsh)?;
    if resp_header.tag == TpmSt::Sessions {
        let _param_size = u32::try_unmarshal(&mut unmarsh)?;
    }
    let resp = CmdT::RespT::try_unmarshal(&mut unmarsh)?;
    if let Some(sessions) = cmd_sessions.as_mut() {
        sessions.read_response_data(cmd, &resp, &mut unmarsh)?;
    }

    if !unmarsh.is_empty() {
        return TssResult::Err(TssTcsError::TpmUnexpected.into());
    }
    Ok((resp, resp_handles))
}

// TODO: Define CmdT at top level?
pub trait AuthorizationArea {
    fn write_session_data<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        handles: &CmdT::Handles,
        buf: &mut [u8],
    ) -> TssResult<usize>;
    fn read_response_data<CmdT: TpmCommand>(
        &mut self,
        cmd: &CmdT,
        resp: &CmdT::RespT,
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()>;
}

impl<T: Session> AuthorizationArea for T {
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
        cmd: &CmdT,
        resp: &CmdT::RespT,
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()> {
        let auth = TpmsAuthResponse::try_unmarshal(buf)?;
        self.validate_auth_response(cmd, resp, &auth)?;

        Ok(())
    }
}

impl<T: Session> AuthorizationArea for [T; 2] {
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
        cmd: &CmdT,
        resp: &CmdT::RespT,
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()> {
        self[0].read_response_data(cmd, resp, buf)?;
        self[1].read_response_data(cmd, resp, buf)
    }
}

impl<T: Session> AuthorizationArea for [T; 3] {
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
        cmd: &CmdT,
        resp: &CmdT::RespT,
        buf: &mut UnmarshalBuf,
    ) -> TssResult<()> {
        self[0].read_response_data(cmd, resp, buf)?;
        self[1].read_response_data(cmd, resp, buf)?;
        self[2].read_response_data(cmd, resp, buf)
    }
}
