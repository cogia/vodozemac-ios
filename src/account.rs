use std::collections::HashMap;
use vodozemac::base64_decode;
use vodozemac::olm::{InboundCreationResult, SessionConfig};
use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use super::{session::Session, OlmMessage, CustomError, IdentityKeys, c_str_to_slice_array, VodozemacError, CIdentityKeys};
use std::string::String;


/// cbindgen:no-export
#[repr(C)]
pub struct Account {
    inner: vodozemac::olm::Account,
}


impl Account {
    pub fn new() -> Self {
        Self {
            inner: vodozemac::olm::Account::new(),
        }
    }

    pub fn identity_keys(&self) -> Result<IdentityKeys, Box<dyn Error>> {
        let identity_keys = self.inner.identity_keys();
        Ok(
            IdentityKeys {
                ed25519: identity_keys.ed25519.to_base64(),
                curve25519: identity_keys.curve25519.to_base64(),
            }
        )
    }

    pub fn from_pickle(pickle: String, pickle_key: String) -> Result<Account, Box<dyn Error>> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let pickle = vodozemac::olm::AccountPickle::from_encrypted(&pickle, pickle_key)
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;


        let inner = vodozemac::olm::Account::from_pickle(pickle);

        Ok(Self { inner })
    }

    pub fn from_libolm_pickle(pickle: String, pickle_key: String) -> Result<Account, Box<dyn Error>> {
        let inner =
            vodozemac::olm::Account::from_libolm_pickle(&pickle, &pickle_key.as_bytes())
                .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        Ok(Self { inner })
    }

    pub fn pickle(&self, pickle_key: String) -> Result<String, Box<dyn Error>> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }

    pub fn ed25519_key(&self) -> String {
        self.inner.ed25519_key().to_base64()
    }

    pub fn curve25519_key(&self) -> String {
        self.inner.curve25519_key().to_base64()
    }

    pub fn sign(&self, message: String) -> String {
        self.inner.sign(&message).to_base64()
    }

    pub fn max_number_of_one_time_keys(&self) -> u32 {
        self.inner.max_number_of_one_time_keys().try_into().unwrap()
    }

    pub fn one_time_keys(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let _keys: HashMap<_, _> = self
            .inner
            .one_time_keys()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect();

        Ok(_keys)
    }

    pub fn generate_one_time_keys(&mut self, count: u32) {
        self.inner.generate_one_time_keys(count.try_into().unwrap());
    }


    pub fn fallback_key(&self) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let _keys: HashMap<String, String> = self
            .inner
            .fallback_key()
            .into_iter()
            .map(|(k, v)| (k.to_base64(), v.to_base64()))
            .collect();

        Ok(_keys)
    }

    pub fn generate_fallback_key(&mut self) {
        self.inner.generate_fallback_key()
        ;
    }

    pub fn mark_keys_as_published(&mut self) {
        self.inner.mark_keys_as_published()
    }

    pub fn create_outbound_session(
        &self,
        identity_key: String,
        one_time_key: String,
        config: &mut SessionConfig
    ) -> Result<Session, Box<dyn Error>> {
        let _config = if config.version() == 2 { vodozemac::megolm::SessionConfig::version_2() } else { vodozemac::megolm::SessionConfig::version_1() };

        let identity_key =
            vodozemac::Curve25519PublicKey::from_base64(&identity_key).map_err(|err: _| Box::new(err) as Box<dyn Error>)?;
        let one_time_key =
            vodozemac::Curve25519PublicKey::from_base64(&one_time_key).map_err(|err: _| Box::new(err) as Box<dyn Error>)?;
        let session = self
            .inner
            .create_outbound_session(SessionConfig::version_2(), identity_key, one_time_key);

        Ok(Session { inner: session })
    }

    pub fn create_inbound_session(
        &mut self,
        identity_key: String,
        message: &OlmMessage,
    ) -> Result<InboundCreationResult, Box<dyn Error>> {
        let identity_key =
            vodozemac::Curve25519PublicKey::from_base64(&identity_key)
                .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let _message = vodozemac::olm::OlmMessage::from_parts(
            message.message_type.try_into().unwrap(),
            &(base64_decode(&c_str_to_slice_array(message.ciphertext)).unwrap())
            // &message.ciphertext.as_bytes()
        )
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        if let vodozemac::olm::OlmMessage::PreKey(m) = _message {
            let res = self
                .inner
                .create_inbound_session(identity_key, &m)
                .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

            Ok(res)
        } else {
            Err(Box::new(CustomError("Invalid message type, expected a pre-key message".to_owned())))
        }
    }
}


#[no_mangle]
pub unsafe extern "C" fn newAccount() -> *mut Account {
    Box::into_raw(Box::new(Account::new()))
}

#[no_mangle]
pub unsafe extern "C" fn accountPickle(ptr: &mut Account, pickle: *const c_char, data: *mut *const c_char) -> VodozemacError {
    //assert!(!ptr.is_null());
    let acc = unsafe { &*ptr };

    let c_str = unsafe { CStr::from_ptr(pickle) };

    let res = match acc.pickle(c_str.to_str().unwrap().to_string()) {
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
pub unsafe extern "C" fn accountIdentityKeys(ptr: &mut Account, data: *mut *const CIdentityKeys) -> VodozemacError {
    let acc = unsafe { &*ptr };
    let res = match acc.identity_keys() {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };
    unsafe {
        let res2 = CIdentityKeys {
            ed25519: CString::new(res.ed25519).expect("CString::new failed").into_raw(),
            curve25519: CString::new(res.curve25519).expect("CString::new failed").into_raw()
        };
        *data = &res2.into()
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountMaxNumberOfOneTimeKeys(ptr: &mut Account, max: *mut *const u32) -> VodozemacError {
    let acc = unsafe { &*ptr };
    unsafe {
        let res = acc.max_number_of_one_time_keys();
        *max = &res;
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountEd25519Key(ptr: &mut Account, data: *mut *const c_char) -> VodozemacError {
    let acc = unsafe { &*ptr };
    unsafe {
        let res = CString::new(acc.ed25519_key()).unwrap();
        *data = res.into_raw()
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountCurve25519Key(ptr: &mut Account, data: *mut *const c_char) -> VodozemacError {
    let acc = unsafe { &*ptr };
    unsafe {
        let res = CString::new(acc.curve25519_key()).unwrap();
        *data = res.into_raw();
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountSign(ptr: &mut Account, message: *const c_char, data: *mut *const c_char) -> VodozemacError {
    let acc = unsafe { &*ptr };
    let local_message = CStr::from_ptr(message).to_str().unwrap();
    unsafe {
        let res = CString::new(acc.sign(local_message.to_string())).unwrap();
        *data = res.into_raw();
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountGenerateOneTimeKeys(ptr: &mut Account, number: u32) -> VodozemacError {
    let acc = unsafe { &mut *ptr };
    let _ = acc.generate_one_time_keys(number);
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountFallbackKeys(ptr: &mut Account) -> VodozemacError {
    let acc = unsafe { &mut *ptr };
    let _ = acc.generate_fallback_key();
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountMarkedAsPublished(ptr: &mut Account) -> VodozemacError {
    let acc = unsafe { &mut *ptr };
    let _ = acc.mark_keys_as_published();
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountFromPickle(pickle: *const c_char, password: *const c_char, ptr:  *mut *mut Account) -> VodozemacError {
    let local_pickle = CStr::from_ptr(pickle).to_str().unwrap();
    let local_password = CStr::from_ptr(password).to_str().unwrap();

    let res = match Account::from_pickle(local_pickle.to_string(), local_password.to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };
    unsafe {
        let acc = Box::into_raw(Box::new(res));
        *ptr = acc;
    }
    VodozemacError::new(0, "Success")

}

#[no_mangle]
pub unsafe extern "C" fn accountFromLibOlmPickle(pickle: *const c_char, password: *const c_char, ptr:  *mut *mut Account) -> VodozemacError {
    let local_pickle = CStr::from_ptr(pickle).to_str().unwrap();
    let local_password = CStr::from_ptr(password).to_str().unwrap();

    let res = match Account::from_libolm_pickle(local_pickle.to_string(), local_password.to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };
    unsafe {
        let acc = Box::into_raw(Box::new(res));
        *ptr = acc;
    }
    VodozemacError::new(0, "Success")

}

#[no_mangle]
pub unsafe extern "C" fn accountOneTimePerKeys(ptr: *mut Account, data: *mut *const c_char) -> VodozemacError {
    let acc = unsafe { &mut *ptr };
    let res = match acc.one_time_keys() {
        Ok(value) => serde_json::to_string(&value).unwrap() ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };
    unsafe {
        let res2 = CString::new(res).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")

}

#[no_mangle]
pub unsafe extern "C" fn accountCreateOutboundSession(
    ptr: *mut Account,
    identity_key: *const c_char,
    one_time_key: *const c_char,
    ptr_session_config: *mut SessionConfig,
    session:  *mut *mut Session
) -> VodozemacError {
    let acc = unsafe { &mut *ptr };
    //c: String,
    //one_time_key: String,
    //config: &mut SessionConfig
    let local_identity_key = CStr::from_ptr(identity_key).to_str().unwrap();
    let local_one_time_key = CStr::from_ptr(one_time_key).to_str().unwrap();

    let config = unsafe { &mut *ptr_session_config };


    let res = match acc.create_outbound_session(local_identity_key.to_string(), local_one_time_key.to_string(), config) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };
    unsafe {
        let sess = Box::into_raw(Box::new(res));
        *session = sess;
    }
    VodozemacError::new(0, "Success")

}

// fallback_key
#[no_mangle]
pub unsafe extern "C" fn accountFallbackKey(
    ptr: *mut Account,
    data: *mut *const c_char
) -> VodozemacError {
    let acc = unsafe { &mut *ptr };
    let res = match acc.fallback_key() {
        Ok(value) => serde_json::to_string(&value).unwrap(),
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        let res2 = CString::new(res).unwrap();
        *data = res2.into_raw();
    }

    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn accountCreateInboundSession(
    ptr: *mut Account,
    identity_key: *const c_char,
    ptr_session_config: *mut OlmMessage,
    session:  *mut *mut Session,
    data: *mut *const c_char
) -> VodozemacError {
    let acc = unsafe { &mut *ptr };
    let local_identity_key = CStr::from_ptr(identity_key).to_str().unwrap();

    let olm_message = unsafe { &mut *ptr_session_config };


    let res = match acc.create_inbound_session(local_identity_key.to_string(), olm_message) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        let sess = Box::into_raw(Box::new(Session { inner: res.session }));
        *session = sess;
    }

    unsafe {
        let res2 = CString::new(res.plaintext).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}
