use crate::errors::Result;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub id: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
}

pub fn encode_jwt(claim: &Claims) -> Result<String> {
    let token = encode(
        &Header::default(),
        claim,
        &EncodingKey::from_secret("secret".as_ref()), // !TODO: use actual secret here
    )?;
    Ok(token)
}

pub fn decode_jwt(token: &str) -> Result<TokenData<Claims>> {
    let token = decode::<Claims>(
        &token,
        &DecodingKey::from_secret("secret".as_ref()),
        &Validation::default(),
    )?;

    Ok(token)
}
