use std::collections::HashMap;
use vodozemac::base64_decode;
use vodozemac::olm::{InboundCreationResult, SessionConfig};
use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use super::{session::Session, OlmMessage, CustomError, IdentityKeys, c_str_to_slice_array, VodozemacError};
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
        *data = c_str.into_raw() // res.as_mut_str().as_ptr()
    }
    VodozemacError::new(0, "Success")
}



