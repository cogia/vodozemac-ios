use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use crate::group_sessions::GroupSession;
use crate::{SessionConfig, VodozemacError};

/// cbindgen:no-export
#[repr(C)]
pub struct Sas {
    inner: vodozemac::sas::Sas,
}


impl Sas {
    pub fn new() -> Self {
        Self {
            inner: vodozemac::sas::Sas::new(),
        }
    }

    pub fn public_key(&self) -> String {
        self.inner.public_key().to_base64()
    }

    pub fn diffie_hellman(self, key: String) -> Result<EstablishedSas, Box<dyn Error>> {
        let sass = self.inner.diffie_hellman_with_raw(&key)
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        Ok(EstablishedSas { inner: sass })
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

/*
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
 */

