use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use std::mem;
use std::os::unix::raw::ino_t;
use crate::group_sessions::GroupSession;
use crate::{CustomError, SessionConfig, VodozemacError};

/// cbindgen:no-export
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Curve25519PublicKey(pub(crate) vodozemac::Curve25519PublicKey);

impl Curve25519PublicKey {
    pub fn from_base64(key: &str) -> Result<Box<Curve25519PublicKey>, Box<dyn Error>> {
        Ok(Curve25519PublicKey(vodozemac::Curve25519PublicKey::from_base64(key).map_err(|err: _| Box::new(err) as Box<dyn Error>)?).into())
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn to_base64(&self) -> String {
        self.0.to_base64()
    }
}

/// cbindgen:no-export
#[repr(C)]
pub struct Sas {
    inner: Option<vodozemac::sas::Sas>,
}


impl Sas {
    pub fn new() -> Self {
        Self {
            inner: Some(vodozemac::sas::Sas::new()),
        }
    }

    pub fn public_key(&mut self) -> String {
        if let Some(sas) = self.inner.take() {
            return sas.public_key().to_base64();
        }
        return String::new();
    }

    pub fn diffie_hellman(&mut self, key: String) -> Result<EstablishedSas, Box<dyn Error>> {
        if let Some(sas) = self.inner.take() {
            let pub_key = Curve25519PublicKey::from_base64(&key).unwrap();
            let sass = sas.diffie_hellman(pub_key.0)
                .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;
            Ok(EstablishedSas { inner: sass })
        } else {
            Err(Box::new(CustomError("Invalid message type, expected a pre-key message".to_owned())))
        }
    }
}

/// cbindgen:no-export
#[repr(C)]
pub struct EstablishedSas {
    inner: vodozemac::sas::EstablishedSas,
}

impl EstablishedSas {
    pub fn bytes(&self, info: String) -> SasBytes {
        let bytes = self.inner.bytes(&info);

        SasBytes { inner: bytes }
    }

    pub fn calculate_mac(&self, input: String, info: String) -> String {
        self.inner.calculate_mac(&input, &info).to_base64()
    }

    pub fn calculate_mac_invalid_base64(&self, input: String, info: String) -> String {
        self.inner.calculate_mac_invalid_base64(&input, &info)
    }

    pub fn verify_mac(&self, input: String, info: String, tag: String) -> Result<(), Box<dyn Error>> {
        let tag = vodozemac::sas::Mac::from_base64(&tag)
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        self.inner
            .verify_mac(&input, &info, &tag)
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        Ok(())
    }
}

/// cbindgen:no-export
#[repr(C)]
pub struct SasBytes {
    inner: vodozemac::sas::SasBytes,
}

impl SasBytes {
    pub fn emoji_indices(&self) -> Vec<u8> {
        self.inner.emoji_indices().to_vec()
    }

    pub fn decimals(&self) -> Vec<u16> {
        let (first, second, third) = self.inner.decimals();

        [first, second, third].to_vec()
    }
}

#[no_mangle]
pub unsafe extern "C" fn newSas() -> *mut Sas {
    Box::into_raw(Box::new(Sas::new()))
}

#[no_mangle]
pub unsafe extern "C" fn newSasPublicKey(ptr: *mut Sas, data: *mut *const c_char) -> VodozemacError {
    let sas = unsafe { &mut *ptr };
    unsafe {
        let res2 = CString::new(sas.public_key()).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn newSasDiffieHellman(ptr: *mut Sas, key: *const c_char, data: *mut *const EstablishedSas) -> VodozemacError {
    let sas = unsafe { &mut *ptr };
    let local_key = CStr::from_ptr(key).to_str().unwrap();
    let res = match sas.diffie_hellman(local_key.to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        let res2 = Box::into_raw(Box::new(res));
        *data = res2
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn establishedSasBytes(ptr: *mut EstablishedSas, info: *const c_char, data: *mut *const SasBytes) -> VodozemacError {
    let es = unsafe { &mut *ptr };
    let local_info = CStr::from_ptr(info).to_str().unwrap();

    unsafe {
        let res2 = Box::into_raw(Box::new(es.bytes(local_info.to_string())));
        *data = res2
    }
    VodozemacError::new(0, "Success")
}


#[no_mangle]
pub unsafe extern "C" fn establishedSasCalculateMac(ptr: *mut EstablishedSas, input: *const c_char, info: *const c_char, data: *mut *const c_char) -> VodozemacError {
    let es = unsafe { &mut *ptr };
    let local_input = CStr::from_ptr(input).to_str().unwrap();
    let local_info = CStr::from_ptr(info).to_str().unwrap();

    unsafe {
        let res2 = CString::new(es.calculate_mac(local_input.to_string(), local_info.to_string())).unwrap();
        *data = res2.into_raw()
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn establishedSasCalculateMacInvalidBase64(ptr: *mut EstablishedSas, input: *const c_char, info: *const c_char, data: *mut *const c_char) -> VodozemacError {
    let es = unsafe { &mut *ptr };
    let local_input = CStr::from_ptr(input).to_str().unwrap();
    let local_info = CStr::from_ptr(info).to_str().unwrap();

    unsafe {
        let res2 = CString::new(es.calculate_mac_invalid_base64(local_input.to_string(), local_info.to_string())).unwrap();
        *data = res2.into_raw()
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn establishedSasVerifyMac(ptr: *mut EstablishedSas, input: *const c_char, info: *const c_char, tag: *const c_char, data: *mut *const i32) -> VodozemacError {
    let es = unsafe { &mut *ptr };
    let local_input = CStr::from_ptr(input).to_str().unwrap();
    let local_info = CStr::from_ptr(info).to_str().unwrap();
    let local_tag = CStr::from_ptr(tag).to_str().unwrap();

    let res = match es.verify_mac(local_input.to_string(), local_info.to_string(), local_tag.to_string()) {
        Ok(_) => 1 ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        *data = &res
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn sasBytesDecimals(ptr: *mut SasBytes, data: *mut *const u16, len: *mut usize) -> VodozemacError {
    let sb = unsafe { &mut *ptr };

    let res = sb.decimals();

    unsafe {
        // Pass the raw pointer and length to C
        *data = res.as_ptr();
        *len = res.len();
    }
    // Prevent Rust from deallocating the vector
    mem::forget(res);
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn sasBytesEmojiIndices(ptr: *mut SasBytes, data: *mut *const u8, len: *mut usize) -> VodozemacError {
    let sb = unsafe { &mut *ptr };

    let res = sb.emoji_indices();

    unsafe {
        // Pass the raw pointer and length to C
        *data = res.as_ptr();
        *len = res.len();
    }
    // Prevent Rust from deallocating the vector
    mem::forget(res);
    VodozemacError::new(0, "Success")
}