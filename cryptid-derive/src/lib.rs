use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Attribute, Meta, Ident};

#[proc_macro_derive(CryptidField, attributes(cryptid))]
pub fn derive_cryptid_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    
    // Extract prefix from #[cryptid(prefix = "user")]
    let prefix = extract_prefix(&input.attrs)
        .expect("CryptidField requires #[cryptid(prefix = \"...\")]");
    
    let marker_name = Ident::new(&format!("{}Marker", struct_name), Span::call_site());
    
    let expanded = quote! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct #marker_name;

        impl cryptid_rs::TypeMarker for #marker_name {
            fn name() -> &'static str {
                #prefix
            }
        }

        impl #struct_name {
            pub fn from(id: u64) -> Self {
                Self(cryptid_rs::Field::from(id))
            }

            pub fn from_str(encoded: &str) -> Result<Self, cryptid_rs::Error> {
                Ok(Self(cryptid_rs::Field::from_str(encoded)?))
            }

            pub fn encode_uuid(self) -> uuid::Uuid {
                self.0.encode_uuid()
            }

            pub fn decode_uuid(uuid: uuid::Uuid) -> Result<Self, cryptid_rs::Error> {
                Ok(Self(cryptid_rs::Field::decode_uuid(uuid)?))
            }
        }

        impl From<#struct_name> for u64 {
            fn from(field: #struct_name) -> Self {
                field.0.into()
            }
        }

        impl From<#struct_name> for i64 {
            fn from(field: #struct_name) -> Self {
                let u64_val: u64 = field.0.into();
                u64_val as i64
            }
        }

        impl std::fmt::Display for #struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::ops::Deref for #struct_name {
            type Target = cryptid_rs::Field<#marker_name>;
            fn deref(&self) -> &Self::Target { &self.0 }
        }

        impl std::ops::DerefMut for #struct_name {
            fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
        }

        // Delegate serde traits to the inner Field<T>
        impl serde::Serialize for #struct_name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: serde::Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for #struct_name {
            fn deserialize<D>(deserializer: D) -> Result<#struct_name, D::Error>
            where D: serde::Deserializer<'de>,
            {
                Ok(Self(cryptid_rs::Field::deserialize(deserializer)?))
            }
        }

        // Delegate SQLx traits to the inner Field<T>
        #[cfg(feature = "sqlx")]
        impl sqlx::Type<sqlx::Postgres> for #struct_name {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                <cryptid_rs::Field<#marker_name> as sqlx::Type<sqlx::Postgres>>::type_info()
            }
        }

        #[cfg(feature = "sqlx")]
        impl<'q> sqlx::Encode<'q, sqlx::Postgres> for #struct_name {
            fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> sqlx::encode::IsNull {
                self.0.encode_by_ref(buf)
            }
        }

        #[cfg(feature = "sqlx")]
        impl<'r> sqlx::Decode<'r, sqlx::Postgres> for #struct_name {
            fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
                Ok(Self(cryptid_rs::Field::decode(value)?))
            }
        }

        // Add From<i64> for SQLx compile-time checking
        impl From<i64> for #struct_name {
            fn from(id: i64) -> Self {
                Self(cryptid_rs::Field::from(id as u64))
            }
        }
    };

    TokenStream::from(expanded)
}

fn extract_prefix(attrs: &[Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("cryptid") {
            if let Meta::List(list) = &attr.meta {
                // Simple parsing - look for prefix = "value"
                let tokens = list.tokens.to_string();
                if let Some(start) = tokens.find("prefix = \"") {
                    let start = start + 10; // length of 'prefix = "'
                    if let Some(end) = tokens[start..].find('"') {
                        return Some(tokens[start..start + end].to_string());
                    }
                }
            }
        }
    }
    None
}