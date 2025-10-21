use once_cell::sync::Lazy;
use std::sync::Mutex;

use crate::field::clear_codec_cache;

static GLOBAL_CONFIG: Lazy<Mutex<Option<Config>>> = Lazy::new(|| Mutex::new(None));

thread_local! {
    static THREAD_LOCAL_CONFIG: std::cell::RefCell<Option<Config>> =
        const { std::cell::RefCell::new(None) };
}

/// Configuring the cryptid library.
#[derive(Clone)]
pub struct Config {
    pub(crate) hmac_length: u8,
    pub(crate) key: Vec<u8>,
    pub(crate) zero_pad_length: u8,
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidMacLength,
    InvalidVersion,
    InvalidZeroPadLength,
}

impl Config {
    /// Creates a new configuration with the given master `key` and other settings in
    /// default values.
    /// - `mac_length` defaults to 4, which is large enough to make guessing impractical
    ///   but still keeps the strings relatively short. High security applications may want
    ///   to use a higher value.
    /// - `zero_pad_length` defaults to 4, which is large enough for most applications
    ///   to never see encoded strings increase in size, while still keeping the strings
    ///   relatively short.
    pub fn new(key: &[u8]) -> Self {
        Config {
            hmac_length: 4,
            key: key.to_vec(),
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
    pub fn set_global(config: Config) {
        let mut global_config = GLOBAL_CONFIG.lock().unwrap();
        *global_config = Some(config);
    }

    /// Sets the thread-local configuration. This takes precedence over the global configuration
    /// for the current thread only.
    pub fn set_thread_local(config: Config) {
        THREAD_LOCAL_CONFIG.with(|tl_config| {
            *tl_config.borrow_mut() = Some(config);
        });
        clear_codec_cache();
    }

    /// Clears the thread-local configuration for the current thread.
    pub fn clear_thread_local() {
        THREAD_LOCAL_CONFIG.with(|tl_config| {
            *tl_config.borrow_mut() = None;
        });
        clear_codec_cache();
    }

    /// Accesses the effective configuration, checking thread-local first, then global.
    /// Thread-local configuration takes precedence over global configuration.
    pub fn effective() -> Option<Config> {
        // Check thread-local first
        let thread_local = THREAD_LOCAL_CONFIG.with(|tl_config| tl_config.borrow().clone());

        if thread_local.is_some() {
            thread_local
        } else {
            // Fall back to global
            GLOBAL_CONFIG.lock().unwrap().clone()
        }
    }

    /// Accesses the global configuration, if set.
    ///
    /// **Note**: Consider using `Config::effective()` instead, which checks
    /// thread-local configuration first.
    pub fn global() -> Option<Config> {
        GLOBAL_CONFIG.lock().unwrap().clone()
    }
}
