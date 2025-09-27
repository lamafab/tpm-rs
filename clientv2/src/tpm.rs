use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
};

use tpm2_rs_base::{
    commands::TpmCommand,
    constants::{TpmCc, TpmSt},
    TpmiStCommandTag,
};
use tpm2_rs_errors::{TssError, TssResult, TssTcsError};
use tpm2_rs_marshalable::{Marshalable, UnmarshalBuf};

use crate::auth_area::AuthorizationArea;

pub const CMD_BUFFER_SIZE: usize = 4096;
pub const RESP_BUFFER_SIZE: usize = 4096;

pub trait Tpm {
    fn transact(&mut self, command: &[u8], response: &mut [u8]) -> TssResult<()>;
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

// A simple file Io protocol.
pub struct FileIoTpm(std::fs::File);

impl FileIoTpm {
    pub fn new<P>(path: P) -> Result<Self, std::io::Error>
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
