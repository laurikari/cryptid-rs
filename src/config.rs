use once_cell::sync::Lazy;
use std::sync::Mutex;

static GLOBAL_CONFIG: Lazy<Mutex<Option<Config>>> = Lazy::new(|| Mutex::new(None));

/// Configuring the cryptid library.
#[derive(Clone)]
pub struct Config<'a> {
    pub(crate) hmac_length: u8,
    pub(crate) key: &'a [u8],
    pub(crate) zero_pad_length: u8,
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidMacLength,
    InvalidVersion,
    InvalidZeroPadLength,
}

impl<'a> Config<'a> {
    /// Creates a new configuration with the given master `key` and other settings in
    /// default values.
    /// - `mac_length` defaults to 4, which is large enough to make guessing impractical
    ///   but still keeps the strings relatively short. High security applications may want
    ///   to use a higher value.
    /// - `zero_pad_length` defaults to 4, which is large enough for most applications
    ///   to never see encoded strings increase in size, while still keeping the strings
    ///   relatively short.
    pub fn new(key: &'a [u8]) -> Self {
        Config {
            hmac_length: 4,
            key,
            zero_pad_length: 4,
        }
    }

    /// Sets the number of bytes in the HMAC.
    /// The value must be between 0 and 8.
    pub fn hmac_length(mut self, hmac_length: u8) -> Result<Self, ConfigError> {
        if hmac_length > 8 {
            Err(ConfigError::InvalidMacLength)
        } else {
            self.hmac_length = hmac_length;
            Ok(self)
        }
    }

    /// Sets the number of bytes to zero-pad numbers before encoding.
    /// The value must be between 0 and 8.
    pub fn zero_pad_length(mut self, zero_pad_length: u8) -> Result<Self, ConfigError> {
        if zero_pad_length > 8 {
            Err(ConfigError::InvalidZeroPadLength)
        } else {
            self.zero_pad_length = zero_pad_length;
            Ok(self)
        }
    }

    /// Sets the global configuration. This should be called before the `Field` type methods
    /// are called.
    pub fn set_global(config: Config<'static>) {
        let mut global_config = GLOBAL_CONFIG.lock().unwrap();
        *global_config = Some(config);
    }

    /// Accesses the global configuration, if set.
    pub fn global() -> Option<Config<'static>> {
        GLOBAL_CONFIG.lock().unwrap().clone()
    }
}
