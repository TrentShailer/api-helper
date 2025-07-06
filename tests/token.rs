#![allow(missing_docs, non_snake_case)]

use base64ct::{Base64UrlUnpadded, Encoding};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::EcGroup,
    nid::Nid,
};
use ts_api_helper::token::{
    Algorithm, JsonWebKey, SigningJsonWebKey, VerifyingJsonWebKey,
    json_web_key::{Curve, JsonWebKeyParameters},
    json_web_token::TokenType,
};

#[test]
fn SignToken_EC_IsCorrect() {
    let ec_key =
        openssl::ec::EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap())
            .unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let mut x = BigNum::new().unwrap();
    let mut y = BigNum::new().unwrap();
    ec_key
        .public_key()
        .affine_coordinates(ec_key.group(), &mut x, &mut y, &mut ctx)
        .unwrap();

    let x = Base64UrlUnpadded::encode_string(&x.to_vec());
    let y = Base64UrlUnpadded::encode_string(&y.to_vec());

    let jwk = JsonWebKey {
        kid: "1".to_string(),
        alg: Algorithm::ES256,
        usage: "sig".to_string(),
        parameters: JsonWebKeyParameters::EC {
            crv: Curve::P256,
            x,
            y,
        },
    };

    let signing_key =
        SigningJsonWebKey::try_from_pem(jwk.clone(), &ec_key.private_key_to_pem().unwrap())
            .unwrap();

    let verifying_key = VerifyingJsonWebKey::try_from(jwk.clone()).unwrap();

    assert!(signing_key.key.public_eq(&verifying_key.key));

    let (token, signature) = signing_key
        .issue(
            "subject".to_string(),
            TokenType::Consent {
                act: "Action".to_string(),
            },
        )
        .unwrap();
    let header = token.header.encode().unwrap();
    let claims = token.claims.encode().unwrap();

    let decoded_jwt = verifying_key
        .verify(&format!("{header}.{claims}.{signature}"))
        .unwrap()
        .unwrap();

    assert!(!decoded_jwt.claims.is_expired());
}
