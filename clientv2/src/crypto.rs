use crate::algo::{AlgoDigestHasher, AlgoDigestHmac};
use tpm2_rs_base::{commands::TpmCommand, Tpm2bDigest, Tpm2bNonce, Tpm2bSimple, TpmaSession};
use tpm2_rs_errors::{TpmRcResult, TssResult};
use tpm2_rs_marshalable::Marshalable;

// TODO: Note that this is simplified.
/// Spec: 9.4.10.2 KDFa()
fn kdfa<M>(key: &[u8], label: &[u8], context: &[u8]) -> TssResult<Vec<u8>>
where
    M: AlgoDigestHmac,
{
    // TODO: Use array?
    let mut buffer = Vec::with_capacity(M::output_size());
    let mut mac = M::new(key);

    let counter = 1u32;
    let bits = M::output_size() as u32 * 8;

    mac.update(&counter.to_be_bytes());
    mac.update(label);
    if label.is_empty() || label.last().expect("TODO") != &0 {
        // > is added only if Label is not present or if the last octet of Label
        // > is not zero.
        mac.update(&[0x00]);
    }
    mac.update(context);
    mac.update(&bits.to_be_bytes());
    buffer.extend_from_slice(mac.finalize().as_ref());

    Ok(buffer)
}

pub fn session_key<M>(
    auth_val: &[u8],
    salt: &[u8],
    nonce_tpm: &Tpm2bNonce,
    nonce_caller: &Tpm2bNonce,
) -> TssResult<Vec<u8>>
where
    M: AlgoDigestHmac,
{
    // TODO: Use array?
    let key = [auth_val, salt].concat();
    let context = [nonce_tpm.get_buffer(), nonce_caller.get_buffer()].concat();

    let buffer = kdfa::<M>(&key, b"ATH", &context)?;
    Ok(buffer)
}

/// Spec: 16.7 Command Parameter Hash
/// > The command parameter hash (cpHash) is used in the computation of a
/// > command authorization HMAC and is included in the digests of session and
/// > command audits (depending on the policy, the cpHash can also be used in
/// > the authorization).
pub fn cp_hash<CmdT: TpmCommand, H: AlgoDigestHasher>(
    cmd: &CmdT,
    cmd_handles: &CmdT::Handles,
    // TODO: Use internal buffer?
    buf: &mut [u8],
) -> TpmRcResult<H::Output> {
    let mut hash = H::new();

    let n = CmdT::CMD_CODE.try_marshal(buf)?;
    hash.update(&buf[..n]);

    let n = cmd_handles.try_marshal(buf)?;
    hash.update(&buf[..n]);

    let n = cmd.try_marshal(buf)?;
    hash.update(&buf[..n]);

    Ok(hash.finalize())
}

/// Spec: 16.8 Response Parameter Hash
/// > The response parameter hash (rpHash) is used in the computation of a
/// > response acknowledgment HMAC and is included in the digest of session and
/// > command audits.
pub fn rp_hash<CmdT: TpmCommand, H: AlgoDigestHasher>(
    resp: &CmdT::RespT,
    // TODO: Use internal buffer?
    buf: &mut [u8],
) -> TpmRcResult<H::Output> {
    let mut hash = H::new();

    // Response code of `TPM_RC_SUCCESS = 0`.
    //
    // > An rpHash needs to be computed only when the responseCode is
    // > TPM_SUCCESS, which means that it is redundant to include the response
    // > code. It is retained for legacy reasons.
    let n = 0u32.try_marshal(buf)?;
    hash.update(&buf[..n]);

    let n = CmdT::CMD_CODE.try_marshal(buf)?;
    hash.update(&buf[..n]);

    let n = resp.try_marshal(buf)?;
    hash.update(&buf[..n]);

    Ok(hash.finalize())
}

/// Spec: 17.6.5 HMAC Computation
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
) -> TpmRcResult<Tpm2bDigest>
where
    M: AlgoDigestHmac,
{
    // TODO: use array?
    let mut buf = vec![0u8; 1_024];

    let n0 = session_key.len();
    let n1 = auth_val.len();

    buf[00..n0 + 00].copy_from_slice(session_key);
    buf[n0..n0 + n1].copy_from_slice(auth_val);

    let key = &buf[..n0 + n1];
    let mut mac = M::new(key);

    mac.update(p_hash);

    let n = nonce_newer.try_marshal(&mut buf)?;
    mac.update(&buf[2..n]); // NOTE: excluding size indicator!

    let n = nonce_older.try_marshal(&mut buf)?;
    mac.update(&buf[2..n]); // NOTE: excluding size indicator!

    let n = session_attributes.try_marshal(&mut buf)?;
    mac.update(&buf[..n]);

    Tpm2bDigest::from_bytes(&mac.finalize().as_ref())
}
