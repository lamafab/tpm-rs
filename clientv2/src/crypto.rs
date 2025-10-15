use crate::algo::{AlgoDigestHasher, AlgoDigestHmac};
use tpm2_rs_base::{
    commands::TpmCommand, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublic, Tpm2bSimple, TpmaSession
};
use tpm2_rs_errors::{TssResult, TssTcsError};
use tpm2_rs_marshalable::Marshalable;

// TODO: Note that this is simplified.
/// Spec (Part 1): 9.4.10.2 KDFa()
fn kdfa<M>(key: &[u8], label: &[u8], context: &[u8]) -> TssResult<M::Output>
where
    M: AlgoDigestHmac,
{
    let mut mac = M::new(key);

    let counter = 1u32;
    let bits = M::OUTPUT_SIZE as u32 * 8;

    mac.update(&counter.to_be_bytes());
    mac.update(label);
    if label.is_empty() || label.last().expect("kdfa label must not be empty") != &0 {
        // > is added only if Label is not present or if the last octet of Label
        // > is not zero.
        mac.update(&[0x00]);
    }
    mac.update(context);
    mac.update(&bits.to_be_bytes());

    Ok(mac.finalize())
}

/// Spec (Part 1): 17.6.8 sessionKey Creation
pub fn session_key<M>(
    auth_val: &[u8],
    salt: &[u8],
    nonce_tpm: &Tpm2bNonce,
    nonce_caller: &Tpm2bNonce,
) -> TssResult<M::Output>
where
    M: AlgoDigestHmac,
{
    let key = [auth_val, salt].concat();
    let context = [nonce_tpm.get_buffer(), nonce_caller.get_buffer()].concat();

    kdfa::<M>(&key, b"ATH", &context)
}

/// Spec (Part 1): 16.7 Command Parameter Hash
/// > The command parameter hash (cpHash) is used in the computation of a
/// > command authorization HMAC and is included in the digests of session and
/// > command audits (depending on the policy, the cpHash can also be used in
/// > the authorization).
pub fn cp_hash<CmdT: TpmCommand, H: AlgoDigestHasher>(
    cmd: &CmdT,
    cmd_handles: &CmdT::Handles,
    object_name: Option<Tpm2bName>,
    wrk_buf: &mut [u8],
) -> TssResult<H::Output> {
    let mut hash = H::new();

    let n = CmdT::CMD_CODE.try_marshal(wrk_buf)?;
    hash.update(&wrk_buf[..n]);

    if let Some(name) = object_name {
        hash.update(name.get_buffer());
    } else {
        let n = cmd_handles.try_marshal(wrk_buf)?;
        hash.update(&wrk_buf[..n]);
    }

    let n = cmd.try_marshal(wrk_buf)?;
    hash.update(&wrk_buf[..n]);

    Ok(hash.finalize())
}

/// Spec (Part 1): 16.8 Response Parameter Hash
/// > The response parameter hash (rpHash) is used in the computation of a
/// > response acknowledgment HMAC and is included in the digest of session and
/// > command audits.
pub fn rp_hash<CmdT: TpmCommand, H: AlgoDigestHasher>(
    resp: &CmdT::RespT,
    wrk_buf: &mut [u8],
) -> TssResult<H::Output> {
    let mut hash = H::new();

    // Response code of `TPM_RC_SUCCESS = 0`.
    //
    // > An rpHash needs to be computed only when the responseCode is
    // > TPM_SUCCESS, which means that it is redundant to include the response
    // > code. It is retained for legacy reasons.
    let n = 0u32.try_marshal(wrk_buf)?;
    hash.update(&wrk_buf[..n]);

    let n = CmdT::CMD_CODE.try_marshal(wrk_buf)?;
    hash.update(&wrk_buf[..n]);

    let n = resp.try_marshal(wrk_buf)?;
    hash.update(&wrk_buf[..n]);

    Ok(hash.finalize())
}

/// Spec (Part 1): 17.6.5 HMAC Computation
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
    wrk_buf: &mut [u8],
) -> TssResult<Tpm2bDigest>
where
    M: AlgoDigestHmac,
{
    let n0 = session_key.len();
    let n1 = auth_val.len();

    if wrk_buf.len() < n0 + n1 {
        return TssResult::Err(TssTcsError::OutOfMemory.into());
    }

    // Reuse buf to concat key.
    wrk_buf[00..n0 + 00].copy_from_slice(session_key);
    wrk_buf[n0..n0 + n1].copy_from_slice(auth_val);
    let key = &wrk_buf[..n0 + n1];

    let mut mac = M::new(key);

    mac.update(p_hash);

    let n = nonce_newer.try_marshal(wrk_buf)?;
    mac.update(&wrk_buf[2..n]); // NOTE: excluding size indicator!

    let n = nonce_older.try_marshal(wrk_buf)?;
    mac.update(&wrk_buf[2..n]); // NOTE: excluding size indicator!

    let n = session_attributes.try_marshal(wrk_buf)?;
    mac.update(&wrk_buf[..n]);

    Tpm2bDigest::from_bytes(&mac.finalize().as_ref()).map_err(Into::into)
}
