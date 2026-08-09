use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use crate::{
    clear_cbcs_cmaf_fragment, clear_cbcs_cmaf_initialization, normalize_clear_cmaf_initialization,
    CbcsContentKey, CbcsDecryptionContext, CmafFragmentTimeline,
};

const ABI_VERSION: u32 = 1;
const CONTENT_KEY_BYTES: usize = 32;

const RESULT_OK: i32 = 0;
const RESULT_INVALID_ARGUMENT: i32 = 1;
const RESULT_OPERATION_FAILED: i32 = 2;
const RESULT_PANIC: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SesameMediaBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl SesameMediaBuffer {
    const fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }

    fn owned(bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::empty();
        }
        let mut bytes = bytes.into_boxed_slice();
        let output = Self {
            data: bytes.as_mut_ptr(),
            len: bytes.len(),
        };
        std::mem::forget(bytes);
        output
    }
}

#[no_mangle]
pub extern "C" fn sesame_media_core_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn sesame_media_buffer_free(buffer: SesameMediaBuffer) {
    if buffer.data.is_null() || buffer.len == 0 {
        return;
    }
    let raw = ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
    unsafe {
        drop(Box::from_raw(raw));
    }
}

#[no_mangle]
pub unsafe extern "C" fn sesame_cmaf_cbcs_context_free(context: *mut CbcsDecryptionContext) {
    if context.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(context));
    }
}

#[no_mangle]
pub unsafe extern "C" fn sesame_cmaf_cbcs_clear_initialization(
    encrypted_data: *const u8,
    encrypted_len: usize,
    clear_out: *mut SesameMediaBuffer,
    context_out: *mut *mut CbcsDecryptionContext,
    error_out: *mut SesameMediaBuffer,
) -> i32 {
    initialize_buffer(clear_out);
    initialize_context(context_out);
    initialize_buffer(error_out);

    if clear_out.is_null() || context_out.is_null() {
        return fail(
            RESULT_INVALID_ARGUMENT,
            error_out,
            "cbcs_missing_output_pointer",
        );
    }

    match catch_unwind(AssertUnwindSafe(|| {
        let encrypted = input_bytes(encrypted_data, encrypted_len)?;
        let initialization = clear_cbcs_cmaf_initialization(encrypted)?;
        Ok::<_, String>(initialization)
    })) {
        Ok(Ok(initialization)) => {
            unsafe {
                ptr::write(clear_out, SesameMediaBuffer::owned(initialization.data));
                ptr::write(context_out, Box::into_raw(Box::new(initialization.context)));
            }
            RESULT_OK
        }
        Ok(Err(error)) => fail(RESULT_OPERATION_FAILED, error_out, &error),
        Err(_) => fail(RESULT_PANIC, error_out, "cbcs_rust_panic"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sesame_cmaf_normalize_clear_initialization(
    clear_data: *const u8,
    clear_len: usize,
    normalized_out: *mut SesameMediaBuffer,
    error_out: *mut SesameMediaBuffer,
) -> i32 {
    initialize_buffer(normalized_out);
    initialize_buffer(error_out);
    if normalized_out.is_null() {
        return fail(
            RESULT_INVALID_ARGUMENT,
            error_out,
            "cbcs_missing_output_pointer",
        );
    }

    match catch_unwind(AssertUnwindSafe(|| {
        let clear = input_bytes(clear_data, clear_len)?;
        normalize_clear_cmaf_initialization(clear)
    })) {
        Ok(Ok(normalized)) => {
            unsafe {
                ptr::write(normalized_out, SesameMediaBuffer::owned(normalized));
            }
            RESULT_OK
        }
        Ok(Err(error)) => fail(RESULT_OPERATION_FAILED, error_out, &error),
        Err(_) => fail(RESULT_PANIC, error_out, "cbcs_rust_panic"),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sesame_cmaf_cbcs_context_key_count(
    context: *const CbcsDecryptionContext,
) -> usize {
    unsafe { context.as_ref() }
        .map(|context| context.key_ids().len())
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn sesame_cmaf_cbcs_context_copy_key_id(
    context: *const CbcsDecryptionContext,
    index: usize,
    key_id_out: *mut u8,
    key_id_len: usize,
) -> i32 {
    if context.is_null() || key_id_out.is_null() || key_id_len < 16 {
        return RESULT_INVALID_ARGUMENT;
    }
    let Some(kid) =
        (unsafe { context.as_ref() }).and_then(|context| context.key_ids().get(index).copied())
    else {
        return RESULT_INVALID_ARGUMENT;
    };
    unsafe {
        ptr::copy_nonoverlapping(kid.as_ptr(), key_id_out, kid.len());
    }
    RESULT_OK
}

#[no_mangle]
pub unsafe extern "C" fn sesame_cmaf_cbcs_clear_fragment(
    encrypted_data: *const u8,
    encrypted_len: usize,
    context: *const CbcsDecryptionContext,
    key_material: *const u8,
    key_count: usize,
    has_timeline: u8,
    base_time_microseconds: u64,
    has_fragment_sequence: u8,
    fragment_sequence: u32,
    clear_out: *mut SesameMediaBuffer,
    error_out: *mut SesameMediaBuffer,
) -> i32 {
    initialize_buffer(clear_out);
    initialize_buffer(error_out);
    if clear_out.is_null() || context.is_null() {
        return fail(
            RESULT_INVALID_ARGUMENT,
            error_out,
            "cbcs_missing_output_pointer",
        );
    }

    match catch_unwind(AssertUnwindSafe(|| {
        let encrypted = input_bytes(encrypted_data, encrypted_len)?;
        let context =
            unsafe { context.as_ref() }.ok_or_else(|| "cbcs_missing_context".to_string())?;
        let key_bytes = input_bytes(
            key_material,
            key_count
                .checked_mul(CONTENT_KEY_BYTES)
                .ok_or_else(|| "cbcs_key_count_overflow".to_string())?,
        )?;
        let keys = key_bytes
            .chunks_exact(CONTENT_KEY_BYTES)
            .map(|bytes| {
                let kid = bytes[..16].try_into().unwrap();
                let cek = bytes[16..].try_into().unwrap();
                CbcsContentKey::new(kid, cek)
            })
            .collect::<Vec<_>>();
        let timeline = (has_timeline != 0).then_some(CmafFragmentTimeline {
            base_time_microseconds,
            fragment_sequence: (has_fragment_sequence != 0).then_some(fragment_sequence),
        });
        clear_cbcs_cmaf_fragment(encrypted, context, &keys, timeline)
    })) {
        Ok(Ok(clear)) => {
            unsafe {
                ptr::write(clear_out, SesameMediaBuffer::owned(clear));
            }
            RESULT_OK
        }
        Ok(Err(error)) => fail(RESULT_OPERATION_FAILED, error_out, &error),
        Err(_) => fail(RESULT_PANIC, error_out, "cbcs_rust_panic"),
    }
}

fn input_bytes<'a>(data: *const u8, len: usize) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err("cbcs_missing_input_pointer".to_string());
    }
    Ok(unsafe { slice::from_raw_parts(data, len) })
}

fn initialize_buffer(output: *mut SesameMediaBuffer) {
    if !output.is_null() {
        unsafe {
            ptr::write(output, SesameMediaBuffer::empty());
        }
    }
}

fn initialize_context(output: *mut *mut CbcsDecryptionContext) {
    if !output.is_null() {
        unsafe {
            ptr::write(output, ptr::null_mut());
        }
    }
}

fn fail(code: i32, error_out: *mut SesameMediaBuffer, message: &str) -> i32 {
    if !error_out.is_null() {
        unsafe {
            ptr::write(
                error_out,
                SesameMediaBuffer::owned(message.as_bytes().to_vec()),
            );
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_rejects_missing_outputs_without_panicking() {
        let mut error = SesameMediaBuffer::empty();
        let result = unsafe {
            sesame_cmaf_cbcs_clear_initialization(
                ptr::null(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut error,
            )
        };
        assert_eq!(result, RESULT_INVALID_ARGUMENT);
        assert_eq!(
            unsafe { slice::from_raw_parts(error.data, error.len) },
            b"cbcs_missing_output_pointer"
        );
        unsafe {
            sesame_media_buffer_free(error);
        }
    }
}
