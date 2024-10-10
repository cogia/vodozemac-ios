use std::error::Error;
use std::ffi::{c_char, CStr, CString};
use super::{CustomError, SessionConfig, VodozemacError};

use vodozemac::megolm::{ExportedSessionKey, MegolmMessage, SessionKey};

/// cbindgen:no-export
#[repr(C)]
pub struct GroupSession {
    pub(super) inner: vodozemac::megolm::GroupSession,
}

impl GroupSession {
    pub fn new(config: &mut SessionConfig) -> Self {
        let _config = if config.version() == 2 { vodozemac::megolm::SessionConfig::version_2() } else { vodozemac::megolm::SessionConfig::version_1() };

        Self {
            inner: vodozemac::megolm::GroupSession::new(_config),
        }
    }

    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    pub fn session_key(&self) -> String {
        self.inner.session_key().to_base64()
    }

    pub fn message_index(&self) -> u32 {
        self.inner.message_index()
    }

    pub fn encrypt(&mut self, plaintext: String) -> String {
        self.inner.encrypt(&plaintext).to_base64()
    }

    pub fn pickle(&self, pickle_key: String) -> Result<String, Box<dyn Error>> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|_| Box::new(CustomError("Invalid pickle key length, expected 32 bytes".to_owned())))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }
    pub fn from_pickle(pickle: String, pickle_key: String) -> Result<GroupSession, Box<dyn Error>> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|_| Box::new(CustomError("Invalid pickle key length, expected 32 bytes".to_owned())))?;
        let pickle = vodozemac::megolm::GroupSessionPickle::from_encrypted(&pickle, pickle_key)
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let session = vodozemac::megolm::GroupSession::from_pickle(pickle);

        Ok(Self { inner: session })
    }
}

#[repr(C)]
pub struct CDecryptedMessage {
    pub plaintext: *const c_char,
    pub message_index: usize,
}

pub struct DecryptedMessage {
    pub plaintext: String,
    pub message_index: u32,
}

/// cbindgen:no-export
#[repr(C)]
pub struct InboundGroupSession {
    pub(super) inner: vodozemac::megolm::InboundGroupSession,
}

impl InboundGroupSession {
    pub fn new(session_key: String, session_config: &SessionConfig) -> Result<InboundGroupSession, Box<dyn Error>> {
        let key = SessionKey::from_base64(&session_key).map_err(|err: _| Box::new(err) as Box<dyn Error>)?;
        let config = if session_config.version() == 2 { vodozemac::megolm::SessionConfig::version_2() } else { vodozemac::megolm::SessionConfig::version_1() };
        Ok(Self {
            inner: vodozemac::megolm::InboundGroupSession::new(&key, config),
        })
    }
    pub fn import(session_key: String, session_config: &SessionConfig) -> Result<InboundGroupSession, Box<dyn Error>> {

        let config = if session_config.version() == 2 { vodozemac::megolm::SessionConfig::version_2() } else { vodozemac::megolm::SessionConfig::version_1() };

        let key = ExportedSessionKey::from_base64(&session_key).map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        Ok(Self {
            inner: vodozemac::megolm::InboundGroupSession::import(&key, config),
        })
    }

    pub fn session_id(&self) -> String {
        self.inner.session_id()
    }

    pub fn first_known_index(&self) -> u32 {
        self.inner.first_known_index()
    }

    pub fn export_at(&mut self, index: u32) -> Option<String> {
        self.inner.export_at(index).map(|k| k.to_base64())
    }

    pub fn decrypt(&mut self, ciphertext: String) -> Result<DecryptedMessage, Box<dyn Error>> {
        let message = MegolmMessage::from_base64(&ciphertext).map_err(|err: _| Box::new(err) as Box<dyn Error>)?;
        let ret = self.inner.decrypt(&message).map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        Ok(DecryptedMessage {
            plaintext: String::from_utf8(ret.plaintext).unwrap(),
            message_index: ret.message_index,
        })
    }
    pub fn pickle(&self, pickle_key: &[u8]) -> Result<String, Box<dyn Error>> {
        let pickle_key: &[u8; 32] = pickle_key
            .try_into()
            .map_err(|_| Box::new(CustomError("Invalid pickle key length, expected 32 bytes".to_owned())))?;

        Ok(self.inner.pickle().encrypt(pickle_key))
    }
    pub fn from_pickle(pickle: String, pickle_key: String) -> Result<InboundGroupSession, Box<dyn Error>> {
        let pickle_key: &[u8; 32] = pickle_key
            .as_bytes()
            .try_into()
            .map_err(|_| Box::new(CustomError("Invalid pickle key length, expected 32 bytes".to_owned())))?;
        let pickle =
            vodozemac::megolm::InboundGroupSessionPickle::from_encrypted(&pickle, pickle_key)
                .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let session = vodozemac::megolm::InboundGroupSession::from_pickle(pickle);

        Ok(Self { inner: session })
    }
    pub fn from_libolm_pickle(
        pickle: String,
        pickle_key: String,
    ) -> Result<InboundGroupSession, Box<dyn Error>> {
        let inner = vodozemac::megolm::InboundGroupSession::from_libolm_pickle(&pickle, &pickle_key.as_bytes())
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        Ok(Self { inner })
    }
}

#[no_mangle]
pub unsafe extern "C" fn newGroupSession(ptr_session_config: *mut SessionConfig) -> *mut GroupSession {
    let config = unsafe { &mut *ptr_session_config };
    Box::into_raw(Box::new(GroupSession::new(config)))
}

#[no_mangle]
pub unsafe extern "C" fn groupSessionSessionId(ptr: *mut GroupSession, data: *mut *const c_char) -> VodozemacError {
    let sess = unsafe { &mut *ptr };
    unsafe {
        let res2 = CString::new(sess.session_id()).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn groupSessionSessionKey(ptr: *mut GroupSession, data: *mut *const c_char) -> VodozemacError {
    let sess = unsafe { &mut *ptr };
    unsafe {
        let res2 = CString::new(sess.session_key()).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn groupSessionMessageIndex(ptr: *mut GroupSession, data: *mut *const usize) -> VodozemacError {
    let sess = unsafe { &mut *ptr };
    unsafe {
        let res =  sess.message_index() as usize;
        *data = &res;
    }
    VodozemacError::new(0, "Success")
}


#[no_mangle]
pub unsafe extern "C" fn groupSessionEncrypt(ptr: *mut GroupSession, plaintext: *const c_char, data: *mut *const c_char) -> VodozemacError {
    let sess = unsafe { &mut *ptr };

    let local_pickle = CStr::from_ptr(plaintext).to_str().unwrap();
    let res = sess.encrypt(local_pickle.to_string());

    unsafe {
        let res2 = CString::new(res).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}


#[no_mangle]
pub unsafe extern "C" fn groupSessionPickle(ptr: *mut GroupSession, password: *const c_char, data: *mut *const c_char) -> VodozemacError {
    let sess = unsafe { &mut *ptr };

    let c_str = unsafe { CStr::from_ptr(password) };

    let res = match sess.pickle(c_str.to_str().unwrap().to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        let res2 = CString::new(res).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn groupSessionFromPickle(pickle: *const c_char, password: *const c_char, ptr:  *mut *const GroupSession) -> VodozemacError {
    let local_pickle = CStr::from_ptr(pickle).to_str().unwrap();
    let local_password = CStr::from_ptr(password).to_str().unwrap();

    let res = match GroupSession::from_pickle(local_pickle.to_string(), local_password.to_string()) {
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
pub unsafe extern "C" fn inboundGroupSessionNew(session_key: *const c_char, ptr_session_config: *mut SessionConfig, ptr:  *mut *const InboundGroupSession) -> VodozemacError {
    let config = unsafe { &mut *ptr_session_config };

    let local_session_key = CStr::from_ptr(session_key).to_str().unwrap();

    let res = match InboundGroupSession::new(local_session_key.to_string(), config) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        let sess = Box::into_raw(Box::new(res));
        *ptr = sess;
    }
    VodozemacError::new(0, "Success")
}

pub unsafe extern "C" fn inboundGroupSessionImport(session_key: *const c_char, ptr_session_config: *mut SessionConfig, ptr:  *mut *const InboundGroupSession) -> VodozemacError {
    let config = unsafe { &mut *ptr_session_config };

    let local_session_key = CStr::from_ptr(session_key).to_str().unwrap();

    let res = match InboundGroupSession::import(local_session_key.to_string(), config) {
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
pub unsafe extern "C" fn inboundGroupSessionSessionId(ptr: *mut InboundGroupSession, data: *mut *const c_char) -> VodozemacError {
    let sess = unsafe { &mut *ptr };
    unsafe {
        let res2 = CString::new(sess.session_id()).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}


#[no_mangle]
pub unsafe extern "C" fn inboundGroupSessionFirstKnownIndex(ptr: *mut InboundGroupSession, data: *mut *const usize) -> VodozemacError {
    let sess = unsafe { &mut *ptr };
    unsafe {
        let res =  sess.first_known_index() as usize;
        *data = &res;
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn inboundGroupSessionExportAt(ptr: *mut InboundGroupSession, index: *const usize, data: *mut *const c_char) -> VodozemacError {
    let sess = unsafe { &mut *ptr };

    let res = sess.export_at(index as u32).unwrap();
    unsafe {
        let res2 = CString::new(res).unwrap();
        *data = res2.into_raw();
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn inboundGroupSessionDecrypt(ptr: *mut InboundGroupSession, ciphertext: *const c_char, data: *mut *const CDecryptedMessage) -> VodozemacError {
    let sess = unsafe { &mut *ptr };

    let local_session_key = CStr::from_ptr(ciphertext).to_str().unwrap();

    let res = match sess.decrypt(local_session_key.to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };

    unsafe {
        let res2 = CDecryptedMessage {
            plaintext: CString::new(res.plaintext).expect("CString::new failed").into_raw(),
            message_index: res.message_index as usize
        };
        *data = &res2.into()
    }
    VodozemacError::new(0, "Success")
}

#[no_mangle]
pub unsafe extern "C" fn inboundGroupSessionPickle(ptr: &mut InboundGroupSession, pickle: *const c_char, data: *mut *const c_char) -> VodozemacError {
    //assert!(!ptr.is_null());
    let sess = unsafe { &*ptr };

    let c_str = unsafe { CStr::from_ptr(pickle) };

    let res = match sess.pickle(c_str.to_str().unwrap().as_bytes()) {
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
pub unsafe extern "C" fn inboundGroupSessionFromPickle(pickle: *const c_char, password: *const c_char, ptr:  *mut *const InboundGroupSession) -> VodozemacError {
    let local_pickle = CStr::from_ptr(pickle).to_str().unwrap();
    let local_password = CStr::from_ptr(password).to_str().unwrap();

    let res = match InboundGroupSession::from_pickle(local_pickle.to_string(), local_password.to_string()) {
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
pub unsafe extern "C" fn inboundGroupSessionFromLibOlmPickle(pickle: *const c_char, password: *const c_char, ptr:  *mut *const InboundGroupSession) -> VodozemacError {
    let local_pickle = CStr::from_ptr(pickle).to_str().unwrap();
    let local_password = CStr::from_ptr(password).to_str().unwrap();

    let res = match InboundGroupSession::from_libolm_pickle(local_pickle.to_string(), local_password.to_string()) {
        Ok(value) => value ,
        Err(error) => return VodozemacError::new(2, error.to_string().as_str())
    };
    unsafe {
        let sess = Box::into_raw(Box::new(res));
        *ptr = sess;
    }
    VodozemacError::new(0, "Success")
}
