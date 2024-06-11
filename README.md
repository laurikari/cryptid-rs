# Cryptid-rs

Cryptid-rs is a library for securely encoding and decoding integers, such as
database primary keys, into strings and back. The encoded string format is
inspired by Stripe's APIs.

For example, a user ID of `123` might be encoded into `user_hHLBCl4rZ3u`.

## Benefits


* **Type-safe**: Encoded strings carry a prefix, preventing accidental
  confusion of IDs of different types.
* **Short**: Compared to UUIDs, cryptid strings are short by default:
  11 characters plus a type prefix.
* **Works with integer database keys**: If you use integers as your database
  primary keys but don't want to expose them directly in your API, this
  library is suitable.
* **Unguessable**: The cryptids are encrypted, making them not only obfuscated
  but also unguessable.
* **Serde and Diesel support**: Define generic types that work directly with
  Serde and Diesel to transparently encode and decode identifiers as they go
  in and out of your API or database layer.

Some of these benefits may also be disadvantages depending on your needs.
Consider carefully if this library is the right choice for you compared to
other solutions, such as using UUIDs as your database keys.

## Example

Use the generic `Field` type to define a type for each kind of object you are
exposing in your public APIs. The `Field` type supports automatic encoding and
decoding with Diesel and Serde.

```rust
use cryptid_rs_rs;
use serde::{Serialize, Deserialize};
use serde_json;

// Define the ExampleId cryptid field type.  The type marker defines the string prefix.
#[derive(Debug)]
pub struct ExampleIdMarker;
impl cryptid_rs::TypeMarker for ExampleIdMarker {
    fn name() -> &'static str { "example" }
}

type ExampleId = cryptid_rs::Field<ExampleIdMarker>;

// The field can then be used in structs, and works automatically with Serde and Diesel.
#[derive(serde::Serialize)]
struct Example {
    pub id: ExampleId,
}

cryptid_rs::Config::set_global(cryptid_rs::Config::new(b"your-secure-key"));
let obj = Example {id: ExampleId::new(12345)};
let obj_str = serde_json::to_string(&obj).unwrap();
assert_eq!(obj_str, "{\"id\":\"example_VgwPy6rwatl\"}");
```

## What's the encryption?

The encryption uses [format-preserving encryption (FPE)](https://en.wikipedia.org/wiki/Format-preserving_encryption)
with AES (FF1 with AES256) and HMAC (SHA256) for integrity checks.

The HMAC is truncated to 4 bytes by default, which is large enough to make
guessing impractical through a rate-limited API but still keeps the strings
relatively short. For high-security applications, consider using a longer HMAC.
