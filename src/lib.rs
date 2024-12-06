//! `cryptid` offers secure encoding and decoding of numbers into URL type safe strings and back,
//! and a generic field type to conveniently manage the process with Serde and Diesel.
//!
//! This library is primarily designed to encrypt raw database IDs in your API, and to transform
//! them into opaque, URL-safe identifiers. This process prevents the guessing of valid IDs,
//! enhancing security against attacks that exploit weak access controls by making object ID
//! enumeration difficult.  You can still enjoy the performance benefits of using monotonically
//! increasing integers as your database keys.
//!
//! The encoded IDs include a customizable object type prefix, inspired by Stripe's API.  This
//! prevents accidentally or intentionally mixing IDs of different types of objects.
//!
//! `cryptid` uses [format-preserving encryption (FPE)](https://en.wikipedia.org/wiki/Format-preserving_encryption)
//! with AES (FF1 with AES256) and HMAC (SHA256) for integrity checks.
//!
//! Please note that leaking the encryption key means you lose all the security benefits.
//! Anyone can then decrypt and encrypt your IDs, and you'll be just as (in)secure as using plain
//! integers in the first place.  You also cannot change the encryption key, unless it's OK that
//! all exposed object identifiers change.
//!
//! # Usage
//!
//! ##  Generic `Field` API (recommended)
//!
//! Use the generic `Field` type do define a type for each type of object you're exposing
//! in your public APIs.  The `Field` type supports automatic encoding and decoding with Diesel
//! and Serde.
//!
//! ```
//! use cryptid_rs;
//! use serde::{Serialize, Deserialize};
//! use serde_json;
//!
//! // Define the ExampleId cryptid field type.  The type marker defines the string prefix.
//! #[derive(Debug)]
//! pub struct ExampleIdMarker;
//! impl cryptid_rs::TypeMarker for ExampleIdMarker {
//!     fn name() -> &'static str { "example" }
//! }
//!
//! type ExampleId = cryptid_rs::Field<ExampleIdMarker>;
//!
//! // The field can then be used in structs, and works automatically with Serde and Diesel.
//! #[derive(serde::Serialize)]
//! struct Example {
//!     pub id: ExampleId,
//! }
//!
//! cryptid_rs::Config::set_global(cryptid_rs::Config::new(b"your-secure-key"));
//! let obj = Example {id: ExampleId::from(12345)};
//! let obj_str = serde_json::to_string(&obj).unwrap();
//! assert_eq!(obj_str, "{\"id\":\"example_VgwPy6rwatl\"}");
//! ```

//!
//! ## Low level API
//!
//! `Codec` provides a simple API to encode and decode integers.
//!
//! ```
//! use cryptid_rs::{Codec, Config};
//!
//! let codec = Codec::new("example", &Config::new(b"your-secure-key"));
//! let encoded = codec.encode(12345);
//! let decoded = codec.decode(&encoded).unwrap();
//! assert_eq!(encoded, "example_VgwPy6rwatl");
//! assert_eq!(decoded, 12345);
//! ```
//!

mod codec;
mod config;
mod field;

pub use codec::{Codec, Error};
pub use config::{Config, ConfigError};
pub use field::{Field, TypeMarker};
