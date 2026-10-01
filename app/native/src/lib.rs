//! C ABI over the `emv` crate for the zkEMV app: one entry point, [`zkemv_call`], that runs a
//! named method on a JSON request and a binary blob, and [`zkemv_free`] for its result.
//!
//! Methods:
//!
//! | Method | Input (JSON) | Blob | Output |
//! |---|---|---|---|
//! | `load_proving_key` | | `.pkp` | `{scheme}` |
//! | `load_verifying_key` | | `.pkv` | `{scheme}` |
//! | `load_ca_table` | | CA table JSON | `{}` |
//! | `issue` | `{scheme, origin, scope, year, month, amount?, currency?}` | | `{id, challenge}` |
//! | `forget` | `{id}` | | `{}` |
//! | `receive` | `{challenge, origin}` | | `{scheme, nonce, year, month, amount, currency}` |
//! | `check_ca` | `{challenge, origin, rid, index}` | | `{}`, or an error if no CA key fits |
//! | `prove` | `{challenge, origin, rid, index, card}` | | proof bytes |
//! | `verify` | `{id, rid, index}` | proof bytes | `{nullifier}` |
//! | `self_test` (feature `self-test`) | `{scheme, origin, year, month}` | | `{scheme, prove_ms, verify_ms, proof_bytes, nullifier}` |
//!
//! Byte strings in JSON are hex. `scheme` is `visa_fdda` or `mastercard_dda`; `scope` is
//! `"unlinkable"`, `"verifier"` or `{"event": hex}`. Keys, the CA table and issued
//! challenges live in process-wide state, shared by all threads.

#![forbid(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_in_result,
    clippy::panic_in_result_fn,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod api;
#[cfg(feature = "self-test")]
mod self_test;

use std::panic::{AssertUnwindSafe, catch_unwind};

/// Bytes owned by this library. Release with [`zkemv_free`].
#[repr(C)]
pub struct ZkemvBytes {
    /// Null if `len` is 0.
    pub ptr: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

/// Result of [`zkemv_call`].
#[repr(C)]
pub struct ZkemvResult {
    /// 0: `data` is the method's output. 1: `data` is a UTF-8 error message.
    pub status: u32,
    /// Output or error message.
    pub data: ZkemvBytes,
}

impl ZkemvBytes {
    fn new(bytes: Vec<u8>) -> Self {
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        let ptr = if len == 0 { std::ptr::null_mut() } else { Box::into_raw(boxed).cast() };
        Self { ptr, len }
    }
}

/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes for `'a`, or `len` must be 0.
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 || ptr.is_null() {
        &[]
    } else {
        // SAFETY: non-null, and the caller guarantees `len` readable bytes.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

/// Runs `method` (UTF-8) on the JSON `input` and the `blob`. Blocking: `prove` and `verify`
/// are CPU-bound. Never unwinds: a panic is returned as an error.
///
/// # Safety
///
/// Each pointer must be valid for reads of its length for the duration of the call, or its
/// length must be 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkemv_call(method: *const u8, method_len: usize, input: *const u8, input_len: usize, blob: *const u8, blob_len: usize) -> ZkemvResult {
    // SAFETY: the caller's contract, per argument.
    let (method, input, blob) = unsafe { (slice(method, method_len), slice(input, input_len), slice(blob, blob_len)) };
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let method = std::str::from_utf8(method).map_err(|_| anyhow::anyhow!("method name is not UTF-8"))?;
        api::call(method, input, blob)
    }));
    let (status, data) = match outcome {
        Ok(Ok(out)) => (0, out),
        Ok(Err(e)) => (1, format!("{e:#}").into_bytes()),
        Err(_) => (1, b"panic in the native library".to_vec()),
    };
    ZkemvResult {
        status,
        data: ZkemvBytes::new(data),
    }
}

/// Releases bytes returned by [`zkemv_call`].
///
/// # Safety
///
/// `bytes` must come from [`zkemv_call`] and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zkemv_free(bytes: ZkemvBytes) {
    if !bytes.ptr.is_null() {
        // SAFETY: `ZkemvBytes::new` made `ptr` and `len` from a boxed slice, not yet freed.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(bytes.ptr, bytes.len)) });
    }
}
