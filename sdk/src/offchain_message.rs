//! Off-chain message container for storing non-transaction messages.

#![cfg(feature = "full")]

use {
    crate::{
        hash::Hash,
        pubkey::Pubkey,
        sanitize::SanitizeError,
        signature::{Signature, Signer},
    },
    num_enum::{IntoPrimitive, TryFromPrimitive},
};

#[cfg(test)]
static_assertions::const_assert_eq!(v0::HEADER_LENGTH, 85);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::MAX_MESSAGE_LENGTH, 65450);
#[cfg(test)]
static_assertions::const_assert_eq!(v0::MAX_MESSAGE_LENGTH_LEDGER, 1147);


#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive, IntoPrimitive)]
pub enum MessageFormat {
    RestrictedAscii,
    LimitedUtf8,
    ExtendedUtf8,
}


#[allow(clippy::arithmetic_side_effects)]
pub mod v0 {
    use {
        crate::{
            hash::{Hash, Hasher},
            packet::PACKET_DATA_SIZE,
            sanitize::SanitizeError,
        },
        super::MessageFormat,
    };
    use solana_program::pubkey::Pubkey;
    use solana_sdk::string_utils::{is_printable_ascii, is_utf8};

    pub const SIGNING_DOMAIN: &[u8; 16] = b"\xffsolana offchain";

    /// Signing domain (16 bytes) + Header version (1 byte) + Application domain (32 bytes) +
    /// + Message format (1 byte) + Signer count (1 bytes) + Signers (signer_count *  32 bytes) +
    /// + Message length (2 bytes)
    /// = 85 bytes
    /// Current cli implementation uses single signer - header size can be estimated up front
    pub const HEADER_LENGTH: usize = 85;

    // Max length of the input message
    pub const MAX_MESSAGE_LENGTH: usize = u16::MAX as usize - HEADER_LENGTH;
    // Max Length of the input message supported by the Ledger
    pub const MAX_MESSAGE_LENGTH_LEDGER: usize = PACKET_DATA_SIZE - HEADER_LENGTH;


    /// OffchainMessage Version 0.
    /// Struct always contains a non-empty valid message.
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct OffchainMessage {
        //Max 16 bytes
        signing_domain: [u8; 16],
        header_version: u8,
        //Max 32 bytes - can be arbitrary data
        application_domain: [u8; 32],
        format: MessageFormat,
        signer_count: u8,
        signers: Vec<Pubkey>,
        message: Vec<u8>,
    }

    impl OffchainMessage {
        /// Construct a new OffchainMessage object from the given message
        pub fn new(message: &[u8], default_signer_pubkey: Pubkey) -> Result<Self, SanitizeError> {
            let format = if message.is_empty() {
                return Err(SanitizeError::InvalidValue);
            } else if message.len() <= MAX_MESSAGE_LENGTH_LEDGER {
                if is_printable_ascii(message) {
                    MessageFormat::RestrictedAscii
                } else if is_utf8(message) {
                    MessageFormat::LimitedUtf8
                } else {
                    return Err(SanitizeError::InvalidValue);
                }
            } else if message.len() <= MAX_MESSAGE_LENGTH {
                if is_utf8(message) {
                    MessageFormat::ExtendedUtf8
                } else {
                    return Err(SanitizeError::InvalidValue);
                }
            } else {
                return Err(SanitizeError::ValueOutOfBounds);
            };
            Ok(Self {
                signing_domain: *SIGNING_DOMAIN,
                header_version: 0,//This implementation is defined for V0 only
                application_domain: [0; 32],
                format,
                signer_count: 1,//CLI supports only one signer
                signers: vec![default_signer_pubkey],
                message: message.to_vec(),
            })
        }

        /// Serialize the message to bytes, including the full header
        /// Message preamble data order:
        /// 1. Signing domain (16 bytes)
        /// 2. Header version (1 byte)
        /// 3. Application domain (32 bytes)
        /// 4. Message format (1 byte)
        /// 5. Signer count (1 bytes)
        /// 6. Signers (signer_count *  32 bytes)
        /// 7. Message length (2 bytes)
        pub fn serialize(&self, data: &mut Vec<u8>) -> Result<(), SanitizeError> {
            // invalid messages shouldn't be possible, but a quick sanity check never hurts
            assert!(!self.message.is_empty() && self.message.len() <= MAX_MESSAGE_LENGTH);

            //Reserve space for header + message
            data.reserve(HEADER_LENGTH.saturating_add(self.message.len()));

            //Signing domain
            data.append(SIGNING_DOMAIN.to_vec().as_mut());

            //Header version
            data.push(0);

            //Application domain
            data.extend_from_slice(&self.application_domain);

            //Message format
            data.push(self.format.into());

            // Signer count
            data.push(self.signer_count);

            // Signers
            for signer in self.signers.iter() {
                data.extend_from_slice(signer.as_ref());
            }

            //Message length
            data.extend_from_slice(&(self.message.len() as u16).to_le_bytes());

            //Message
            data.extend_from_slice(&self.message);

            Ok(())
        }

        /// Deserialize the message from bytes that include a full header
        pub fn deserialize(data: &[u8]) -> Result<Self, SanitizeError> {
            // validate data length
            if data.len() <= HEADER_LENGTH || data.len() > HEADER_LENGTH + MAX_MESSAGE_LENGTH {
                return Err(SanitizeError::ValueOutOfBounds);
            }
            //We know that header is at least 85 bytes long and message is not empty - using raw indexes should be safe

            let signing_domain: [u8; 16] = data[0..16].try_into().unwrap();
            let header_version: u8 = data[16];
            let application_domain: [u8; 32] = data[17..49].try_into().unwrap();

            // decode header
            let format =
                MessageFormat::try_from(data[49]).map_err(|_| SanitizeError::InvalidValue)?;

            //Signer count
            let signer_count = data[50];

            //Signers
            let signers: Vec<Pubkey> = vec![Pubkey::new_from_array(data[51..83].try_into().unwrap())];


            let message_len = u16::from_le_bytes([data[83], data[84]]) as usize;

            // check header
            if HEADER_LENGTH.saturating_add(message_len) != data.len() {
                return Err(SanitizeError::InvalidValue);
            }

            let message = &data[HEADER_LENGTH..];
            // check format
            let is_valid = match format {
                MessageFormat::RestrictedAscii => {
                    (message.len() <= MAX_MESSAGE_LENGTH_LEDGER) && is_printable_ascii(message)
                }
                MessageFormat::LimitedUtf8 => {
                    (message.len() <= MAX_MESSAGE_LENGTH_LEDGER) && is_utf8(message)
                }
                MessageFormat::ExtendedUtf8 => (message.len() <= MAX_MESSAGE_LENGTH) && is_utf8(message),
            };

            if is_valid {
                Ok(Self {
                    signing_domain,
                    header_version,
                    application_domain,
                    format,
                    signer_count,
                    signers,
                    message: message.to_vec(),
                })
            } else {
                Err(SanitizeError::InvalidValue)
            }
        }

        /// Compute the SHA256 hash of the serialized off-chain message
        pub fn hash(serialized_message: &[u8]) -> Result<Hash, SanitizeError> {
            let mut hasher = Hasher::default();
            hasher.hash(serialized_message);
            Ok(hasher.result())
        }

        pub fn get_format(&self) -> MessageFormat {
            self.format
        }

        pub fn get_message(&self) -> &Vec<u8> {
            &self.message
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OffchainMessage {
    V0(v0::OffchainMessage),
}

impl OffchainMessage {
    /// Construct a new OffchainMessage object from the given version and message
    pub fn new(version: u8, message: &[u8], default_signer_pubkey: &Pubkey) -> Result<Self, SanitizeError> {
        match version {
            0 => Ok(Self::V0(v0::OffchainMessage::new(message, *default_signer_pubkey)?)),
            _ => Err(SanitizeError::ValueOutOfBounds),
        }
    }

    /// Serialize the off-chain message to bytes including full header
    pub fn serialize(&self) -> Result<Vec<u8>, SanitizeError> {
        let mut data = Vec::new();

        // serialize version and call version specific serializer
        match self {
            Self::V0(msg) => {
                msg.serialize(&mut data)?;
            }
        }
        Ok(data)
    }

    /// Deserialize the off-chain message from bytes that include full header
    /// Used only in tests
    pub fn deserialize(version: u8, data: &[u8]) -> Result<Self, SanitizeError> {

        // let version = data[v0::SIGNING_DOMAIN.len()];
        // let data = &data[v0::SIGNING_DOMAIN.len().saturating_add(1)..];
        match version {
            0 => {
                if data.len() <= v0::HEADER_LENGTH || data.len() > v0::HEADER_LENGTH + v0::MAX_MESSAGE_LENGTH {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                Ok(Self::V0(v0::OffchainMessage::deserialize(data)?))
            }
            _ => Err(SanitizeError::InvalidValue),
        }
    }

    /// Compute the hash of the off-chain message
    pub fn hash(&self) -> Result<Hash, SanitizeError> {
        match self {
            // Hash input message contents
            Self::V0(_) => v0::OffchainMessage::hash(self.get_message()),
        }
    }

    pub fn get_version(&self) -> u8 {
        match self {
            Self::V0(_) => 0,
        }
    }

    pub fn get_format(&self) -> MessageFormat {
        match self {
            Self::V0(msg) => msg.get_format(),
        }
    }

    pub fn get_message(&self) -> &Vec<u8> {
        match self {
            Self::V0(msg) => msg.get_message(),
        }
    }

    /// Sign the message with provided keypair
    pub fn sign(&self, signer: &dyn Signer) -> Result<Signature, SanitizeError> {
        Ok(signer.sign_message(&self.serialize()?))
    }

    /// Verify that the message signature is valid for the given public key
    pub fn verify(&self, signer: &Pubkey, signature: &Signature) -> Result<bool, SanitizeError> {
        Ok(signature.verify(signer.as_ref(), &self.serialize()?))
    }
}

#[cfg(test)]
mod tests {
    use {crate::signature::Keypair, std::str::FromStr, super::*};

    #[test]
    fn test_offchain_message_extended_utf8(){
        let text_message = "Ł".repeat(v0::MAX_MESSAGE_LENGTH_LEDGER.saturating_add(1));
        let message = OffchainMessage::new(0, text_message.as_ref(), &Pubkey::default()).unwrap();
        assert_eq!(message.get_format(), MessageFormat::ExtendedUtf8);
    }


    ///Header versions others than 0 should return error
    #[test]
    fn test_offchain_message_invalid_header_version() {
        let message = OffchainMessage::new(1, b"Test Message", &Pubkey::default());
        assert!(matches!(message,  Err(SanitizeError::ValueOutOfBounds)));
    }

    #[test]
    fn test_offchain_message_empty_message() {
        let message = OffchainMessage::new(0, b"", &Pubkey::default());
        assert!(matches!(message, Err(SanitizeError::InvalidValue)));
    }

    #[test]
    fn test_offchain_message_too_long_utf8() {
        let message = OffchainMessage::new(0, &[0; v0::MAX_MESSAGE_LENGTH.saturating_add(1)], &Pubkey::default());
        assert!(matches!(message, Err(SanitizeError::ValueOutOfBounds)));
    }

    #[test]
    fn test_offchain_message_invalid_utf8() {
        let message = OffchainMessage::new(0, &[0xF1], &Pubkey::default());
        assert!(matches!(message, Err(SanitizeError::InvalidValue)));
    }

    #[test]
    fn test_offchain_message_invalid_utf8_long_message() {
        let message = OffchainMessage::new(0, &[0xF1; v0::MAX_MESSAGE_LENGTH_LEDGER.saturating_add(1)], &Pubkey::default());
        assert!(matches!(message, Err(SanitizeError::InvalidValue)));
    }

    #[test]
    fn test_offchain_message_ascii() {
        let message = OffchainMessage::new(0, b"Test Message", &Pubkey::default()).unwrap();

        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_format(), MessageFormat::RestrictedAscii);
        assert_eq!(message.get_message().as_slice(), b"Test Message");
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.get_format() == MessageFormat::RestrictedAscii)
        );
        let serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12,
            0, 84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101
        ];
        let hash = Hash::from_str("DHMr3vK1BJ5RzfwAmjzkayGyEs3ouKUhHzZdYRG5migZ").unwrap();
        assert_eq!(message.serialize().unwrap(), serialized);
        assert_eq!(message.hash().unwrap(), hash);
        assert_eq!(message, OffchainMessage::deserialize(0, &serialized).unwrap());
    }

    #[test]
    fn test_offchain_message_utf8() {
        let message = OffchainMessage::new(0, "Тестовое сообщение".as_bytes(), &Pubkey::default()).unwrap();
        assert_eq!(message.get_version(), 0);
        assert_eq!(message.get_format(), MessageFormat::LimitedUtf8);
        assert_eq!(
            message.get_message().as_slice(),
            "Тестовое сообщение".as_bytes()
        );
        assert!(
            matches!(message, OffchainMessage::V0(ref msg) if msg.get_format() == MessageFormat::LimitedUtf8)
        );
        let serialized = [
            255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35,
            0, 208, 162, 208, 181, 209, 129, 209, 130, 208, 190, 208, 178, 208, 190, 208, 181, 32, 209, 129,
            208, 190, 208, 190, 208, 177, 209, 137, 208, 181, 208, 189, 208, 184, 208, 181
        ];
        let hash = Hash::from_str("GTARP1PJqT7JoqnjN5TCJDzzoxB7MqtsBvA2b5hbNc7c").unwrap();
        assert_eq!(message.serialize().unwrap(), serialized);
        assert_eq!(message.hash().unwrap(), hash);
        assert_eq!(message, OffchainMessage::deserialize(0, &serialized).unwrap());
    }

    #[test]
    fn test_offchain_message_sign_and_verify() {
        let message = OffchainMessage::new(0, b"Test Message", &Pubkey::default()).unwrap();
        let keypair = Keypair::new();
        let signature = message.sign(&keypair).unwrap();
        assert!(message.verify(&keypair.pubkey(), &signature).unwrap());
    }
}
