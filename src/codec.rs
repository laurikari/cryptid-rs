use std::fmt;

use aes::Aes256;
use base62;
use fpe::ff1::{BinaryNumeralString, FF1};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::Config;

type HmacSha256 = Hmac<Sha256>;

/// Error returned for encode/decode errors.
#[derive(Debug, PartialEq)]
pub enum Error {
    DecodingFailed,
    DecryptionFailed,
    EncryptionFailed,
    IncorrectMAC,
    InvalidDataLength,
    InvalidPrefix { received: String, expected: String },
    SentinelMismatch { received: u8, expected: u8 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::DecodingFailed => {
                write!(f, "Decoding string failed")
            }
            Error::DecryptionFailed => {
                write!(f, "FF1 decryption failed")
            }
            Error::EncryptionFailed => {
                write!(f, "FF1 encryption failed")
            }
            Error::IncorrectMAC => {
                write!(f, "Incorrect MAC")
            }
            Error::InvalidDataLength => {
                write!(f, "Invalid data length")
            }
            Error::SentinelMismatch { received, expected } => {
                write!(f, "Sentinel byte was {}, expected {}", received, expected)
            }
            Error::InvalidPrefix { received, expected } => {
                write!(f, "Prefix was {}, expected {}", received, expected)
            }
        }
    }
}

impl From<base62::DecodeError> for Error {
    fn from(_: base62::DecodeError) -> Error {
        Error::DecodingFailed
    }
}

impl std::error::Error for Error {}

// Maximum number of bytes we can base62 encode (an u128).
const MAX_BUFFER: usize = 16;

// The sentinel byte, in case we don't fill the full 16 bytes.
const SENTINEL: u8 = 1;

/// Core encoder/decoder.
pub struct Codec {
    ff1: FF1<Aes256>,
    hmac: HmacSha256,
    hmac_length: usize,
    prefix: String,
    zero_pad_length: usize,
}

impl Codec {
    /// Creates a new `Codec` instance with the given name and key.
    ///
    /// The `name` is used as a prefix in the encoded output and to derive a prefix-specifc
    /// key together with the master `key`.
    ///
    /// **Security note:** In order to be secure, you must provide a secure random `key`
    /// with sufficient entropy, and manage it appropriately.
    ///
    /// # Arguments
    ///
    /// * `name` - A string slice that holds the name of the codec.
    /// * `key` - A byte slice that holds the master key for encryption and MAC.
    ///
    /// # Returns
    ///
    /// A new instance of `Codec`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptid_rs::{Config, Codec};
    ///
    /// let codec = Codec::new("example", &Config::new(b"your-secure-key"));
    /// ```
    pub fn new(name: &str, config: &Config) -> Codec {
        let hkdf = Hkdf::<Sha256>::new(None, config.key);
        let mut ff1_key = [0u8; 32];
        let mut hmac_key = [0u8; 32];
        hkdf.expand(format!("{}/ff1", name).as_bytes(), &mut ff1_key)
            .expect("Length 32 should be valid");
        hkdf.expand(format!("{}/hmac", name).as_bytes(), &mut hmac_key)
            .expect("Length 32 should be valid");
        Codec {
            ff1: FF1::<Aes256>::new(&ff1_key, 2).expect("Radix 2 should be valid"),
            hmac: HmacSha256::new_from_slice(&hmac_key).expect("Key length 32 should be valid"),
            hmac_length: config.hmac_length as usize,
            prefix: format!("{}_", name),
            zero_pad_length: config.zero_pad_length as usize,
        }
    }

    /// Encodes a given numeric value into a secure string representation.
    ///
    /// This method applies format-preserving encryption to the number and
    /// then encodes it into a base62 string with a prefix. It also appends
    /// an HMAC for integrity verification.
    ///
    /// # Arguments
    ///
    /// * `num` - The 64-bit unsigned integer to be encoded.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` containing the encoded string if successful,
    /// or an `Error` if encoding fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptid_rs::{Codec, Config};
    ///
    /// let codec = Codec::new("example", &Config::new(b"your-secure-key"));
    /// let encoded = codec.encode(12345);
    ///
    /// assert_eq!(encoded, "example_VgwPy6rwatl");
    /// ```
    pub fn encode(&self, num: u64) -> String {
        let encoded = base62::encode(self.encode_u128(num));
        format!("{}{}", self.prefix, encoded)
    }

    /// Encrypts `num` into a 128 bit value.  Note that high order bits may be zeroes,
    /// so that a short string representation can be made.
    fn encode_u128(&self, num: u64) -> u128 {
        let bytes = encrypt_number(
            &self.ff1,
            &self.hmac,
            self.hmac_length,
            self.zero_pad_length,
            num,
        );
        let mut num_array = [0u8; MAX_BUFFER];
        num_array[..bytes.len()].copy_from_slice(&bytes);
        if bytes.len() < num_array.len() {
            num_array[bytes.len()] = SENTINEL;
        }
        u128::from_le_bytes(num_array)
    }

    /// Encrypts `num` into an UUID.
    pub fn encode_uuid(&self, num: u64) -> Uuid {
        // 8 bytes for hmac and 8 bytes for payload gets us a nice random 128 bit value.
        let vec = encrypt_number(&self.ff1, &self.hmac, 8, 8, num);
        let num = u128::from_le_bytes(vec.try_into().expect("Should have exactly 16 bytes"));
        Uuid::from_u128_le(num)
    }

    /// Decodes a previously encoded string back into its original numeric value.
    ///
    /// This method first verifies the integrity of the encoded data using HMAC,
    /// and then applies format-preserving decryption to retrieve the original number.
    /// It expects the encoded data to start with the correct prefix.
    ///
    /// # Arguments
    ///
    /// * `encoded` - A string slice representing the encoded data.
    ///
    /// # Returns
    ///
    /// A `Result` which is `Ok` containing the decoded 64-bit unsigned integer if successful,
    /// or an `Error` if decoding fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptid_rs::{Codec, Config};
    ///
    /// let codec = Codec::new("example", &Config::new(b"your-secure-key"));
    /// let decoded = codec.decode("example_VgwPy6rwatl").unwrap();
    ///
    /// assert_eq!(decoded, 12345);
    /// ```
    pub fn decode(&self, encoded: &str) -> Result<u64, Error> {
        // Ensure prefix matches (from last underscore).
        let received = match encoded.rfind('_') {
            None => "".to_string(),
            Some(i) => encoded[..i + 1].to_string(),
        };
        if received != self.prefix {
            let expected = self.prefix.clone();
            return Err(Error::InvalidPrefix { received, expected });
        }

        let tail = &encoded[self.prefix.len()..];
        let num = base62::decode(tail).map_err(Error::from)?;
        let num_array = num.to_le_bytes();

        let length;
        if self.hmac_length + self.zero_pad_length < MAX_BUFFER {
            length = last_nonzero(&num_array);
            if num_array[length] != SENTINEL {
                return Err(Error::SentinelMismatch {
                    received: num_array[length],
                    expected: SENTINEL,
                });
            }
        } else {
            length = MAX_BUFFER;
        }

        decrypt_number(self, &num_array[..length])
    }
}

fn last_nonzero(bytes: &[u8]) -> usize {
    bytes.iter().rposition(|&b| b != 0).unwrap_or(0)
}

// Returns a memory representanion of `num` as a byte vector in little-endian byte
// order, leaving out trailing zero bytes beyond `min_length`.
fn num_to_le_vec(num: u64, min_length: usize) -> Vec<u8> {
    let bytes = num.to_le_bytes();
    let prefix_length = (last_nonzero(&bytes) + 1).max(min_length);
    bytes[..prefix_length].to_vec()
}

fn le_vec_to_num(bytes: &[u8]) -> u64 {
    let mut arr = [0; 8];
    arr[..bytes.len()].copy_from_slice(bytes);
    u64::from_le_bytes(arr)
}

fn encrypt_number(
    ff1: &FF1<Aes256>,
    hmac: &HmacSha256,
    hmac_length: usize,
    zero_pad_length: usize,
    num: u64,
) -> Vec<u8> {
    // Encrypt `num` using form-preserving encryption.
    let pt = num_to_le_vec(num, zero_pad_length);
    let encrypted_num = ff1
        .encrypt(&[], &BinaryNumeralString::from_bytes_le(&pt))
        .expect("Radix 2 should be valid")
        .to_bytes_le();

    // Compute a truncated MAC from the ciphertext.
    let mut hmac: HmacSha256 = hmac.clone();
    hmac.update(&encrypted_num);
    let truncated_mac = &hmac.finalize().into_bytes()[..hmac_length];

    // Return the combined bytes.
    let mut result = encrypted_num.to_vec();
    result.extend_from_slice(truncated_mac);

    result
}

fn decrypt_number(codec: &Codec, encrypted_data: &[u8]) -> Result<u64, Error> {
    if encrypted_data.len() < codec.hmac_length + codec.zero_pad_length {
        return Err(Error::InvalidDataLength);
    }
    let (encrypted_num, received_mac) =
        encrypted_data.split_at(encrypted_data.len() - codec.hmac_length);

    // Verify MAC
    let mut hmac: HmacSha256 = codec.hmac.clone();
    hmac.update(&encrypted_num);
    let truncated_mac = &hmac.finalize().into_bytes()[..codec.hmac_length];
    if truncated_mac != received_mac {
        return Err(Error::IncorrectMAC);
    }

    // Decrypt the number
    let decrypted_num = codec
        .ff1
        .decrypt(&[], &BinaryNumeralString::from_bytes_le(encrypted_num))
        .map_err(|_| Error::DecryptionFailed)?;

    // Convert decrypted bytes back to number
    let num: u64 = le_vec_to_num(&decrypted_num.to_bytes_le());
    Ok(num)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Uniform, Rng};

    #[test]
    fn test_defaults() {
        let codec = Codec::new("test", &Config::new(b"Test key here"));
        let test_cases = vec![
            (0, "test_g1HdsEGpXp5"),
            (1, "test_bTPc8uxHEwv"),
            (2, "test_dZ0iJdcLBgB"),
            (123, "test_hHLBCl4rZ3u"),
            (u64::MAX, "test_20cMzlnhTkILdJzWt"),
        ];

        for (input, expected) in test_cases {
            assert_eq!(codec.encode(input), expected);
            assert_eq!(codec.decode(expected).unwrap(), input);
        }
    }

    #[test]
    fn test_uuid() {
        let codec = Codec::new("test", &Config::new(b"Test key here"));
        let test_cases = [
            (0, "59142369-adeb-8ef9-a1be-28f61c05d4d6"),
            (1, "93196956-2d32-d8d2-54f7-9a86fc765f3a"),
            (2, "3c10f25c-005e-6f6f-87a9-781efe02d14d"),
            (123, "571fd9d5-e133-f7b0-b0df-f444e4dd1127"),
            (u64::MAX, "a3b06cf5-dd4d-3f09-4000-9d3519d4d6c2"),
        ];

        for &(input, expected) in &test_cases {
            assert_eq!(codec.encode_uuid(input), Uuid::parse_str(expected).unwrap());
        }
    }

    #[test]
    fn test_long() {
        let config = Config::new(b"Test key here")
            .hmac_length(8)
            .unwrap()
            .zero_pad_length(8)
            .unwrap();
        let codec = Codec::new("test", &config);
        assert_eq!(codec.encode(0), "test_6XNFaHOCeuIBNvRT4pIrVZ");
        assert_eq!(codec.encode(1), "test_1m9BJW23Jk5hSIlfPxoboZ");
        assert_eq!(codec.encode(2), "test_2MpvWPgnp5j1dIqFnJVOjU");
        assert_eq!(codec.encode(123), "test_1BirgT1ZJhfSsKFLgxA5gt");
        assert_eq!(codec.encode(u64::MAX), "test_5vegfyOLrrmwtgznQByI4J");
        assert_eq!(codec.decode("test_6XNFaHOCeuIBNvRT4pIrVZ").unwrap(), 0);
        assert_eq!(codec.decode("test_1m9BJW23Jk5hSIlfPxoboZ").unwrap(), 1);
        assert_eq!(codec.decode("test_2MpvWPgnp5j1dIqFnJVOjU").unwrap(), 2);
        assert_eq!(codec.decode("test_1BirgT1ZJhfSsKFLgxA5gt").unwrap(), 123);
        assert_eq!(
            codec.decode("test_5vegfyOLrrmwtgznQByI4J").unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn test_short() {
        let config = Config::new(b"Test key here")
            .hmac_length(0)
            .unwrap()
            .zero_pad_length(3)
            .unwrap();
        let codec = Codec::new("test", &config);
        assert_eq!(codec.encode(0), "test_1zG8O");
        assert_eq!(codec.encode(1), "test_1R8PN");
        assert_eq!(codec.encode(2), "test_1nzgo");
        assert_eq!(codec.encode(123), "test_1YqNT");
        assert_eq!(codec.encode(u64::MAX), "test_Mlu72Yai97j");
        assert_eq!(codec.decode("test_1zG8O").unwrap(), 0);
        assert_eq!(codec.decode("test_1R8PN").unwrap(), 1);
        assert_eq!(codec.decode("test_1nzgo").unwrap(), 2);
        assert_eq!(codec.decode("test_1YqNT").unwrap(), 123);
        assert_eq!(codec.decode("test_Mlu72Yai97j").unwrap(), u64::MAX);

        // Without HMAC, pretty much anything decodes to some number.
        assert_eq!(codec.decode("test_1helloall").unwrap(), 20580488769766);
    }

    #[test]
    fn test_decode_errors() {
        let codec = Codec::new("test", &Config::new(b"Test key here"));

        assert_eq!(
            codec.decode("hHLBCl4rZ3u"),
            Err(Error::InvalidPrefix {
                received: "".to_string(),
                expected: "test_".to_string()
            })
        );

        assert_eq!(
            codec.decode("_hHLBCl4rZ3u"),
            Err(Error::InvalidPrefix {
                received: "_".to_string(),
                expected: "test_".to_string()
            })
        );

        assert_eq!(
            codec.decode("wrong_hHLBCl4rZ3u"),
            Err(Error::InvalidPrefix {
                received: "wrong_".to_string(),
                expected: "test_".to_string()
            })
        );

        assert_eq!(
            codec.decode("test_iHLBCl4rZ3u"),
            Err(Error::SentinelMismatch {
                received: 2,
                expected: SENTINEL,
            })
        );

        // Tampering with any part gives a MAC error.
        assert_eq!(codec.decode("test_hHLBCl4rZ3v"), Err(Error::IncorrectMAC));
        assert_eq!(codec.decode("test_hHMBCl4rZ3u"), Err(Error::IncorrectMAC));

        // Invalid characters aren't allowed.
        assert_eq!(codec.decode("test_hHLBCl+rZ3u"), Err(Error::DecodingFailed));

        // And just to validate the above, check that the correct string does decode.
        assert_eq!(codec.decode("test_hHLBCl4rZ3u"), Ok(123));
    }

    #[test]
    fn test_random_roundtrips() {
        let codec = Codec::new("test", &Config::new(b"Test key here"));
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0u64, u64::MAX);

        for _ in 0..10_000 {
            let number = rng.sample(range);
            let encoded = codec.encode(number);
            let decoded = codec.decode(&encoded).expect("Decoding failed");

            assert_eq!(decoded, number, "Failed at number: {}", number);
        }
    }
}
