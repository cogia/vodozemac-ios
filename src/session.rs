use std::error::Error;
use vodozemac::{base64_decode, base64_encode};
use super::{c_str_to_slice_array, CustomError, OlmMessage};

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
            &base64_decode(&c_str_to_slice_array(message.ciphertext)).unwrap()
        )
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let decrypted_message = self.inner.decrypt(&_message)
            .map_err(|err: _| Box::new(err) as Box<dyn Error>)?;

        let decrypted_message = String::from_utf8(decrypted_message)
            .map_err(|err| Box::new(err) as Box<dyn Error>)?;

        Ok(decrypted_message)
    }
}

