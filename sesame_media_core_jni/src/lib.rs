use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{JByteArray, JClass};
use jni::sys::{jboolean, jbyteArray, jint, jlong};
use jni::JNIEnv;
use sesame_cmaf_cbcs::{
    clear_cbcs_cmaf_fragment, clear_cbcs_cmaf_initialization, normalize_clear_cmaf_initialization,
    CbcsContentKey, CbcsDecryptionContext, CmafFragmentTimeline,
};
use zeroize::Zeroize;

const ABI_VERSION: jint = 1;
const CONTENT_KEY_RECORD_BYTES: usize = 32;

struct NativeSession {
    clear_initialization: Vec<u8>,
    context: CbcsDecryptionContext,
    key_ids: Vec<[u8; 16]>,
}

static NEXT_SESSION_ID: AtomicI64 = AtomicI64::new(1);
static SESSIONS: OnceLock<Mutex<HashMap<i64, Arc<NativeSession>>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<i64, Arc<NativeSession>>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn with_jni_result<T>(
    env: &mut JNIEnv,
    fallback: T,
    operation: impl FnOnce(&mut JNIEnv) -> Result<T, String>,
) -> T {
    match catch_unwind(AssertUnwindSafe(|| operation(env))) {
        Ok(Ok(value)) => value,
        Ok(Err(message)) => {
            throw_media_error(env, &message);
            fallback
        }
        Err(_) => {
            throw_media_error(env, "cbcs_rust_panic");
            fallback
        }
    }
}

fn throw_media_error(env: &mut JNIEnv, message: &str) {
    let _ = env.throw_new("java/lang/IllegalStateException", message);
}

fn read_bytes(env: &mut JNIEnv, value: &JByteArray, name: &str) -> Result<Vec<u8>, String> {
    env.convert_byte_array(value)
        .map_err(|error| format!("jni_invalid_{name}:{error}"))
}

fn write_bytes(env: &mut JNIEnv, bytes: &[u8]) -> Result<jbyteArray, String> {
    env.byte_array_from_slice(bytes)
        .map(|array| array.into_raw())
        .map_err(|error| format!("jni_byte_array_failed:{error}"))
}

fn session(handle: jlong) -> Result<Arc<NativeSession>, String> {
    if handle <= 0 {
        return Err("cbcs_invalid_session".to_string());
    }
    sessions()
        .lock()
        .map_err(|_| "cbcs_session_registry_poisoned".to_string())?
        .get(&handle)
        .cloned()
        .ok_or_else(|| "cbcs_unknown_session".to_string())
}

#[no_mangle]
pub extern "system" fn Java_com_sesameware_mediacore_NativeBridge_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    ABI_VERSION
}

#[no_mangle]
pub extern "system" fn Java_com_sesameware_mediacore_NativeBridge_nativeCreateSession(
    mut env: JNIEnv,
    _class: JClass,
    encrypted: JByteArray,
) -> jlong {
    with_jni_result(&mut env, 0, |env| {
        let encrypted = read_bytes(env, &encrypted, "initialization")?;
        let initialization = clear_cbcs_cmaf_initialization(&encrypted)?;
        let key_ids = initialization.context.key_ids();
        if key_ids.is_empty() {
            return Err("cbcs_missing_context_keys".to_string());
        }
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        if id <= 0 {
            return Err("cbcs_session_id_overflow".to_string());
        }
        sessions()
            .lock()
            .map_err(|_| "cbcs_session_registry_poisoned".to_string())?
            .insert(
                id,
                Arc::new(NativeSession {
                    clear_initialization: initialization.data,
                    context: initialization.context,
                    key_ids,
                }),
            );
        Ok(id)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_sesameware_mediacore_NativeBridge_nativeClearInitialization(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    with_jni_result(&mut env, std::ptr::null_mut(), |env| {
        let session = session(handle)?;
        write_bytes(env, &session.clear_initialization)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_sesameware_mediacore_NativeBridge_nativeKeyIds(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    with_jni_result(&mut env, std::ptr::null_mut(), |env| {
        let session = session(handle)?;
        let mut bytes = Vec::with_capacity(session.key_ids.len() * 16);
        for key_id in &session.key_ids {
            bytes.extend_from_slice(key_id);
        }
        write_bytes(env, &bytes)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_sesameware_mediacore_NativeBridge_nativeClearFragment(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    encrypted: JByteArray,
    key_material: JByteArray,
    has_timeline: jboolean,
    base_time_microseconds: jlong,
    has_fragment_sequence: jboolean,
    fragment_sequence: jint,
) -> jbyteArray {
    with_jni_result(&mut env, std::ptr::null_mut(), |env| {
        let session = session(handle)?;
        let encrypted = read_bytes(env, &encrypted, "fragment")?;
        let mut key_material = read_bytes(env, &key_material, "key_material")?;
        let result = (|| {
            if key_material.is_empty() || key_material.len() % CONTENT_KEY_RECORD_BYTES != 0 {
                return Err("cbcs_invalid_key_material".to_string());
            }
            let keys = key_material
                .chunks_exact(CONTENT_KEY_RECORD_BYTES)
                .map(|record| {
                    let kid: [u8; 16] = record[..16]
                        .try_into()
                        .map_err(|_| "cbcs_invalid_key_id".to_string())?;
                    let cek: [u8; 16] = record[16..]
                        .try_into()
                        .map_err(|_| "cbcs_invalid_content_key".to_string())?;
                    Ok(CbcsContentKey::new(kid, cek))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let timeline = if has_timeline != 0 {
                Some(CmafFragmentTimeline {
                    base_time_microseconds: u64::try_from(base_time_microseconds)
                        .map_err(|_| "cbcs_invalid_base_time".to_string())?,
                    fragment_sequence: if has_fragment_sequence != 0 {
                        Some(
                            u32::try_from(fragment_sequence)
                                .map_err(|_| "cbcs_invalid_fragment_sequence".to_string())?,
                        )
                    } else {
                        None
                    },
                })
            } else {
                None
            };
            let clear = clear_cbcs_cmaf_fragment(&encrypted, &session.context, &keys, timeline)?;
            write_bytes(env, &clear)
        })();
        key_material.zeroize();
        result
    })
}

#[no_mangle]
pub extern "system" fn Java_com_sesameware_mediacore_NativeBridge_nativeNormalizeClearInitialization(
    mut env: JNIEnv,
    _class: JClass,
    clear: JByteArray,
) -> jbyteArray {
    with_jni_result(&mut env, std::ptr::null_mut(), |env| {
        let clear = read_bytes(env, &clear, "clear_initialization")?;
        let normalized = normalize_clear_cmaf_initialization(&clear)?;
        write_bytes(env, &normalized)
    })
}

#[no_mangle]
pub extern "system" fn Java_com_sesameware_mediacore_NativeBridge_nativeDestroySession(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    with_jni_result(&mut env, (), |_env| {
        if handle <= 0 {
            return Ok(());
        }
        sessions()
            .lock()
            .map_err(|_| "cbcs_session_registry_poisoned".to_string())?
            .remove(&handle);
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_rejects_unknown_sessions() {
        assert_eq!(session(0).err().unwrap(), "cbcs_invalid_session");
        assert_eq!(session(i64::MAX).err().unwrap(), "cbcs_unknown_session");
    }

    #[test]
    fn key_record_size_matches_public_contract() {
        assert_eq!(CONTENT_KEY_RECORD_BYTES, 16 + 16);
    }
}
