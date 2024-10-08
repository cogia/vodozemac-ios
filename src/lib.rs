mod account;
mod session;

use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use std::fmt;

#[repr(C)]
pub struct OlmMessage {
    pub ciphertext: *const c_char,
    pub message_type: u32,
}

impl OlmMessage {
    pub fn new(message_type: u32, ciphertext: String) -> Self {
        Self {
            ciphertext: CString::new(ciphertext).unwrap().into_raw(),
            message_type,
        }
    }
}

#[repr(C)]
pub struct SessionConfig {
    _version: u8,
}

impl SessionConfig {
    /// Get the numeric version of this `SessionConfig`.
    pub const fn version(&self) -> u8 {
        self._version
    }

    /// Create a `SessionConfig` for the Olm version 1. This version of Olm will
    /// use AES-256 and HMAC with a truncated MAC to encrypt individual
    /// messages. The MAC will be truncated to 8 bytes.
    pub const fn version_1() -> Self {
        SessionConfig { _version: 1 }
    }

    /// Create a `SessionConfig` for the Olm version 2. This version of Olm will
    /// use AES-256 and HMAC to encrypt individual messages. The MAC won't be
    /// truncated.
    pub const fn version_2() -> Self {
        SessionConfig { _version: 2 }
    }
}

#[repr(C)]
pub struct IdentityKeys {
    pub ed25519: String,
    pub curve25519: String,
}

#[no_mangle]
pub unsafe extern "C" fn sessionConfigV2() -> SessionConfig {
    SessionConfig::version_2()
}

#[no_mangle]
pub unsafe extern "C" fn sessionConfigV1() -> SessionConfig {
    SessionConfig::version_1()
}

#[no_mangle]
pub unsafe extern "C" fn getVersionSessionConfig(config: &mut SessionConfig) -> u8 {
    config.version()
}

#[no_mangle]
pub unsafe extern "C" fn newOlmMessage(message_type: u32, ciphertext: *const c_char) -> OlmMessage {
    OlmMessage { message_type, ciphertext }
}

pub fn c_str_to_slice_array(c_str: *const c_char) ->  Vec<u8>  {
    let vec = unsafe { CStr::from_ptr(c_str) }
        .to_bytes()
        .to_vec();

    vec
}

#[derive(Debug)]
struct CustomError(String);

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for CustomError {}


#[repr(C)]
pub struct  VodozemacError {
    code: i32,
    message: *mut c_char,
}

impl VodozemacError {
    fn new(code: i32, message: &str) -> Self {
        let c_message = CString::new(message).expect("CString::new failed");
        VodozemacError {
            code,
            message: c_message.into_raw(),
        }
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if !s.is_null() {
            let _ = CString::from_raw(s);
        }
    }
}