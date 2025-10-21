use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

#[cfg(feature = "diesel")]
use diesel::deserialize::{self, FromSql, Queryable};
#[cfg(feature = "diesel")]
use diesel::expression::AsExpression;
#[cfg(feature = "diesel")]
use diesel::pg::{Pg, PgValue};
#[cfg(feature = "diesel")]
use diesel::serialize::{self, Output, ToSql};
#[cfg(feature = "diesel")]
use diesel::sql_types::BigInt;

#[cfg(feature = "sqlx")]
use sqlx::{postgres::PgTypeInfo, Postgres, Type};

use crate::{Codec, Config};

thread_local! {
    static CODEC_CACHE: RefCell<HashMap<String, Arc<Codec>>> = RefCell::new(HashMap::new());
}

/// Clears the thread-local codec cache. This should be called when the thread-local
/// configuration changes to ensure codecs use the new configuration.
pub fn clear_codec_cache() {
    CODEC_CACHE.with(|cache| {
        cache.borrow_mut().clear();
    });
}

fn get_or_create_codec(name: &str) -> Arc<Codec> {
    CODEC_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(codec) = cache.get(name) {
            codec.clone()
        } else {
            let codec = Arc::new(Codec::new(name, &Config::effective().unwrap()));
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
/// Traits are also provided for both Diesel and SQLx compatibility with Postgres BigInt fields.
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
#[cfg_attr(feature = "diesel", derive(AsExpression))]
#[cfg_attr(feature = "diesel", diesel(sql_type = BigInt))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<T: TypeMarker> {
    id: u64,
    _marker: std::marker::PhantomData<T>,
}

// Implement Hash only when T implements Hash
impl<T: TypeMarker + std::hash::Hash> std::hash::Hash for Field<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self._marker.hash(state);
    }
}

impl<T: TypeMarker> From<Field<T>> for u64 {
    /// Returns the raw `u64` value.
    fn from(field: Field<T>) -> Self {
        field.id
    }
}

impl<T: TypeMarker> fmt::Display for Field<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let codec_name = T::name();
        let codec = get_or_create_codec(codec_name);
        write!(f, "{}", codec.encode(self.id))
    }
}

impl<T: TypeMarker> Field<T> {
    /// Creates a `Field<T>` value from a `u64`.
    ///
    /// This method converts a `u64` into a `Field<T>`, effectively changing its type.
    pub fn from(id: u64) -> Self {
        Field {
            id,
            _marker: std::marker::PhantomData,
        }
    }

    /// Encrypts the ID into a `Uuid` value.
    pub fn encode_uuid(self) -> Uuid {
        let codec_name = T::name();
        let codec = get_or_create_codec(codec_name);
        codec.encode_uuid(self.id)
    }

    /// Decrypts a `Uuid` value back into a `Field<T>`.
    pub fn decode_uuid(uuid: Uuid) -> Result<Self, crate::codec::Error> {
        let codec_name = T::name();
        let codec = get_or_create_codec(codec_name);
        let id = codec.decode_uuid(uuid)?;
        Ok(Field::from(id))
    }
}

// For queries with single values (not tables)
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

// For queries with single values (not tables)
impl<'de, T: TypeMarker> Deserialize<'de> for Field<T> {
    fn deserialize<D>(deserializer: D) -> Result<Field<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let text = String::deserialize(deserializer)?;
        let codec_name = T::name();
        let codec = get_or_create_codec(codec_name);
        let id = codec.decode(&text).map_err(Error::custom)?;
        Ok(Field {
            id,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<T: TypeMarker> std::str::FromStr for Field<T> {
    type Err = crate::codec::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let codec_name = T::name();
        let codec = get_or_create_codec(codec_name);
        let id = codec.decode(s)?;
        Ok(Field::from(id))
    }
}

// -- Diesel compatibility for postgres --
#[cfg(feature = "diesel")]
impl<T: TypeMarker> ToSql<BigInt, Pg> for Field<T> {
    fn to_sql(&self, out: &mut Output<'_, '_, Pg>) -> serialize::Result {
        <i64 as ToSql<BigInt, Pg>>::to_sql(&(self.id as i64), &mut out.reborrow())
    }
}

#[cfg(feature = "diesel")]
impl<T: TypeMarker> FromSql<BigInt, Pg> for Field<T> {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        let id = <i64 as FromSql<BigInt, Pg>>::from_sql(bytes)?;
        Ok(Field::from(id as u64))
    }
}

#[cfg(feature = "diesel")]
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

// -- SQLx compatibility for postgres --

#[cfg(feature = "sqlx")]
// Type implementation for SQLx
impl<T: TypeMarker> Type<Postgres> for Field<T> {
    fn type_info() -> PgTypeInfo {
        <i64 as Type<Postgres>>::type_info()
    }
}

#[cfg(feature = "sqlx")]
// Encode implementation for SQLx (for parameters)
impl<'q, T: TypeMarker> sqlx::Encode<'q, Postgres> for Field<T> {
    fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> sqlx::encode::IsNull {
        let id = self.id as i64;
        <i64 as sqlx::Encode<Postgres>>::encode_by_ref(&id, buf)
    }
}

#[cfg(feature = "sqlx")]
// Decode implementation for SQLx (for query results)
impl<'r, T: TypeMarker> sqlx::Decode<'r, Postgres> for Field<T> {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let id = <i64 as sqlx::Decode<Postgres>>::decode(value)?;
        Ok(Field {
            id: id as u64,
            _marker: std::marker::PhantomData,
        })
    }
}
