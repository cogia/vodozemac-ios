use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use vodozemac::{base64_decode, base64_encode};
use crate::account::Account;
use super::{c_str_to_slice_array, CustomError, OlmMessage, VodozemacError};


/// cbindgen:no-export
#[repr(C)]
pub struct Session {
    pub(super) inner: vodozemac::olm::Session,
}

impl Session {
    pub fn pickle(&self, pickle_key: String) -> Result<String, Box<dyn Error>> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|_| Box::new(CustomError("Invalid pickle key length, expected 32 bytes".to_owned())))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    pub fn from_pickle(pickle: String, pickle_key: String) -> Result<Session, Box<dyn Error>> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|_| Box::new(CustomError("Invalid pickle key length, expected 32 bytes".to_owned())))?;
        let pickle = vodozemac::olm::SessionPickle::from_encrypted(&pickle, pickle_key)
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let session = vodozemac::olm::Session::from_pickle(pickle);

        Ok(Self { inner: session })
    }

    pub fn from_libolm_pickle(pickle: String, pickle_key: String) -> Result<Session, Box<dyn Error>> {
        let session =
            vodozemac::olm::Session::from_libolm_pickle(&pickle, &pickle_key.as_bytes()).map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        Ok(Self { inner: session })
    }

    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    pub fn session_matches(&self, message: &OlmMessage) -> bool {
        let message =
            vodozemac::olm::OlmMessage::from_parts(
                message.message_type.try_into().unwrap(),
                &base64_decode(&c_str_to_slice_array(message.ciphertext)).unwrap()
            );

        match message {
            Ok(m) => {
                if let vodozemac::olm::OlmMessage::PreKey(m) = m {
                    self.inner.session_keys() == m.session_keys()
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    pub fn encrypt(&mut self, plaintext: String) -> OlmMessage {
        let message = self.inner.encrypt(plaintext);

        let (message_type, ciphertext) = message.to_parts();

        crate::OlmMessage::new(message_type.try_into().unwrap(), base64_encode(ciphertext))
    }

    pub fn decrypt(&mut self, message: &OlmMessage) -> Result<String, Box<dyn Error>> {
        /*let _message =
            vodozemac::olm::OlmMessage::from_parts(message.message_type.try_into().unwrap(), &message.ciphertext.as_bytes())
                .map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?;

        Ok(self.inner.decrypt(&_message).map_err(|err: _| Error::new(Status::GenericFailure, err.to_string().to_owned()))?)*/
        let _message = vodozemac::olm::OlmMessage::from_parts(
            message.message_type.try_into().unwrap(),
            &base64_decode(&c_str_to_slice_array(message.ciphertext))?
        )
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let decrypted_message = self.inner.decrypt(&_message)
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let decrypted_message = String::from_utf8(decrypted_message)
            .map_err(|err| Box::new(err) as Box<dyn Error>)?;

        Ok(decrypted_message)
    }
}


#[no_mangle]
pub unsafe extern "C" fn sessionPickle(ptr: &mut Session, pickle: *const c_char, data: *mut *const c_char) -> VodozemacError {
    //assert!(!ptr.is_null());
    let sess = unsafe { &*ptr };

    let c_str = unsafe { CStr::from_ptr(pickle) };

    let res = match sess.pickle(c_str.to_str().unwrap().to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        let c_str = CString::new(res).unwrap();
        *data = c_str.into_raw()
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn sessionFromPickle(pickle: *const c_char, password: *const c_char, ptr:  *mut *mut Session) -> VodozemacError {
    let local_pickle = CStr::from_ptr(pickle).to_str().unwrap();
    let local_password = CStr::from_ptr(password).to_str().unwrap();

    let res = match Session::from_pickle(local_pickle.to_string(), local_password.to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };
    unsafe {
        let sess = Box::into_raw(Box::new(res));
        *ptr = sess;
    }
    VodozemacError::new(0, "Success")

}

#[no_mangle]
pub unsafe extern "C" fn sessionFromLibOlmPickle(pickle: *const c_char, password: *const c_char, ptr:  *mut *mut Session) -> VodozemacError {
    let local_pickle = CStr::from_ptr(pickle).to_str().unwrap();
    let local_password = CStr::from_ptr(password).to_str().unwrap();

    let res = match Session::from_libolm_pickle(local_pickle.to_string(), local_password.to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };
    unsafe {
        let sess = Box::into_raw(Box::new(res));
        *ptr = sess;
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn sessionSessionId(ptr: *mut Session, data: *mut *const c_char) -> VodozemacError {
    let sess = unsafe { &mut *ptr };
    unsafe {
        let res2 = CString::new(sess.session_id()).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn sessionSessionMatches(ptr: *mut Session, ptr_session_config: *mut OlmMessage, data: *mut *const usize) -> VodozemacError {
    let sess = unsafe { &mut *ptr };
    let olm_message = unsafe { &mut *ptr_session_config };

    let res = sess.session_matches(olm_message) as usize;

    unsafe {
        *data = &res;
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn sessionEncrypt(ptr: *mut Session, plaintext: *mut c_char, data: *mut *const OlmMessage) -> VodozemacError {
    let sess = unsafe { &mut *ptr };

    let local_pickle = CStr::from_ptr(plaintext).to_str().unwrap();
    let res = sess.encrypt(local_pickle.to_string());
    unsafe {
        *data = &res;
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn sessionDecrypt(ptr: *mut Session, message: *mut OlmMessage, data: *mut *const c_char) -> VodozemacError {
    let sess = unsafe { &mut *ptr };
    let olm_message = unsafe { &mut *message };

    let res = match sess.decrypt(olm_message) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        let res2 = CString::new(res).unwrap();
        *data = res2.into_raw();
    }

    VodozemacError::new(0, "Success")
}
/*

        pub fn decrypt(&mut self, message: &OlmMessage) -> Result<String, Box<dyn Error>> {
     */