use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use diesel::deserialize::{self, FromSql, Queryable};
use diesel::expression::AsExpression;
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::BigInt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::{Codec, Config};

thread_local! {
    static CODEC_CACHE: RefCell<HashMap<String, Arc<Codec>>> = RefCell::new(HashMap::new());
}

fn get_or_create_codec(name: &str) -> Arc<Codec> {
    CODEC_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(codec) = cache.get(name) {
            codec.clone()
        } else {
            let codec = Arc::new(Codec::new(name, &Config::global().unwrap()));
            cache.insert(name.to_string(), codec.clone());
            codec
        }
    })
}

pub trait TypeMarker: std::fmt::Debug {
    fn name() -> &'static str;
}

/// An generic type-safe object ID field (a wrapped u64).
///
/// When serialized with Serde, the number is automatically encrypted and encoded
/// into a URL safe string.  Deserialization decodes and decrypts the string back
/// to an integer.  The string has an object type specific prefix defined in
/// the type marker's `fn name()`.
///
/// Traits are also provided for Diesel compatibility with Postgres BigInt fields.
///
/// # Examples
///
/// ```
/// use cryptid_rs;
/// use serde::{Serialize, Deserialize};
/// use serde_json;
///
/// #[derive(Clone, Copy, Debug)]
/// pub struct ExampleIdMarker;
/// impl cryptid_rs::TypeMarker for ExampleIdMarker {
///     fn name() -> &'static str { "example" }
/// }
///
/// type ExampleId = cryptid_rs::Field<ExampleIdMarker>;
///
/// #[derive(serde::Serialize)]
/// struct Example {
///     pub id: ExampleId,
/// }
///
/// cryptid_rs::Config::set_global(cryptid_rs::Config::new(b"your-secure-key"));
/// let obj = Example {id: ExampleId::from(12345)};
/// let obj_str = serde_json::to_string(&obj).unwrap();
/// assert_eq!(obj_str, "{\"id\":\"example_VgwPy6rwatl\"}");
/// ```
#[derive(AsExpression, Debug, Clone, Copy)]
#[diesel(sql_type = BigInt)]
pub struct Field<T: TypeMarker> {
    id: u64,
    _marker: std::marker::PhantomData<T>,
}

impl<T: TypeMarker> From<Field<T>> for u64 {
    /// Returns the raw `u64` value.
    fn from(field: Field<T>) -> Self {
        field.id
    }
}

impl<T: TypeMarker> fmt::Display for Field<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Field {{ id: {}, marker: {} }}", self.id, T::name())
    }
}

impl<T: TypeMarker> Field<T> {
    /// Creates a `Field<T>` value from a `u64`.
    ///
    /// This method converts a `u64` into a `Field<T>`, effectively changing its type.
    pub fn from(id: u64) -> Self {
        Field {
            id: id,
            _marker: std::marker::PhantomData,
        }
    }

    /// Encrypts the ID into a `Uuid` value.
    pub fn encode_uuid(self) -> Uuid {
        let codec_name = T::name();
        let codec = get_or_create_codec(codec_name);
        codec.encode_uuid(self.id)
    }
}

impl<T: TypeMarker> Serialize for Field<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let codec_name = T::name();
        let codec = get_or_create_codec(codec_name);
        serializer.serialize_str(&codec.encode(self.id))
    }
}

impl<'de, T: TypeMarker> Deserialize<'de> for Field<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let codec_name = T::name();
        let codec = get_or_create_codec(codec_name);
        let id = codec.decode(&encoded).map_err(serde::de::Error::custom)?;
        Ok(Field::from(id))
    }
}

impl<T: TypeMarker> ToSql<BigInt, Pg> for Field<T> {
    fn to_sql(&self, out: &mut Output<'_, '_, Pg>) -> serialize::Result {
        <i64 as ToSql<BigInt, Pg>>::to_sql(&(self.id as i64), &mut out.reborrow())
    }
}

impl<T: TypeMarker> FromSql<BigInt, Pg> for Field<T> {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        let id = <i64 as FromSql<BigInt, Pg>>::from_sql(bytes)?;
        Ok(Field::from(id as u64))
    }
}

impl<T> Queryable<BigInt, Pg> for Field<T>
where
    T: TypeMarker,
{
    type Row = <i64 as Queryable<BigInt, Pg>>::Row;

    fn build(row: Self::Row) -> deserialize::Result<Self> {
        let id = i64::build(row)?;
        Ok(Field::from(id as u64))
    }
}
