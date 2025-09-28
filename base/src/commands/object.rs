//! [TPM2.0 1.83] 12 Object Commands

use crate::commands::{Marshalable, TpmCommand};
use crate::constants::{TpmCc, TpmHandle};
use crate::{Tpm2bName, Tpm2bPublic, Tpm2bSensitive, TpmiDhObject, TpmiRhHierarchy};

/// [TPM2.0 1.83] 12.1 TPM2_Create (Command)
pub struct CreateCmd {}

/// [TPM2.0 1.83] 12.2 TPM2_Load (Command)
pub struct LoadCmd {}

/// [TPM2.0 1.83] 12.3 TPM2_LoadExternal (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct LoadExternalCmd {
    pub in_private: Tpm2bSensitive,
    pub in_public: Tpm2bPublic,
    pub hierarchy: TpmiRhHierarchy,
}

impl TpmCommand for LoadExternalCmd {
    const CMD_CODE: TpmCc = TpmCc::LoadExternal;

    type Handles = ();
    type RespT = LoadExternalResp;
    /// Object handle of type TPM_HT_TRANSIENT for the loaded object.
    type RespHandles = TpmHandle;
}

/// [TPM2.0 1.83] 12.3 TPM2_LoadExternal (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct LoadExternalResp {
    pub name: Tpm2bName,
}

/// [TPM2.0 1.83] 12.4 TPM2_ReadPublic (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct ReadPublicCmd {
    // No parameters.
}

impl TpmCommand for ReadPublicCmd {
    const CMD_CODE: TpmCc = TpmCc::ReadPublic;

    /// TPM handle of an object
    type Handles = TpmiDhObject;
    type RespT = ReadPublicResp;
    /// Object handle of type TPM_HT_TRANSIENT for the loaded object.
    type RespHandles = ();
}

/// [TPM2.0 1.83] 12.4 TPM2_ReadPublic (Command)
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Marshalable)]
pub struct ReadPublicResp {
    pub out_public: Tpm2bPublic,
    pub name: Tpm2bName,
    pub qualified_name: Tpm2bName,
}

/// [TPM2.0 1.83] 12.5 TPM2_ActivateCredential (Command)
pub struct ActivateCredentialCmd {}

/// [TPM2.0 1.83] 12.6 TPM2_MakeCredential (Command)
pub struct MakeCredentialCmd {}

/// [TPM2.0 1.83] 12.7 TPM2_Unseal (Command)
pub struct UnsealCmd {}

/// [TPM2.0 1.83] 12.8 TPM2_ObjectChangeAuth (Command)
pub struct ObjectChangeAuthCmd {}

/// [TPM2.0 1.83] 12.9 TPM2_CreateLoaded (Command)
pub struct CreateLoadedCmd {}
