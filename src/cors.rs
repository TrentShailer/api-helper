use core::net::{Ipv4Addr, Ipv6Addr};

use http::{
    HeaderName, Method, Uri,
    header::{ACCEPT, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE},
};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Cors layer where the common HTTP methods, headers, and localhost are all allowed by default.
pub fn cors_layer(
    additional_allowed_origins: Vec<Uri>,
    additional_allowed_headers: &[HeaderName],
    additional_exposed_headers: &[HeaderName],
) -> CorsLayer {
    let mut allowed_headers = vec![AUTHORIZATION, ACCEPT, CONTENT_TYPE];
    allowed_headers.extend_from_slice(additional_allowed_headers);

    let mut exposed_headers = vec![AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE];
    exposed_headers.extend_from_slice(additional_exposed_headers);

    let allowed_methods = [
        Method::OPTIONS,
        Method::HEAD,
        Method::GET,
        Method::PUT,
        Method::POST,
        Method::DELETE,
    ];

    let allowed_origins = AllowOrigin::predicate(move |header, _| {
        let Ok(origin) = header.to_str() else {
            return false;
        };
        let Ok(origin) = Uri::try_from(origin) else {
            return false;
        };
        let Some(host) = origin.host() else {
            return false;
        };

        // Allow localhost regardless of port or scheme.
        if host == "localhost"
            || host.parse::<Ipv4Addr>() == Ok(Ipv4Addr::LOCALHOST)
            || host.parse::<Ipv6Addr>() == Ok(Ipv6Addr::LOCALHOST)
        {
            return true;
        }

        // Allow origin if it matches the scheme, host, and port of an allowed origin.
        additional_allowed_origins.iter().any(|allowed_origin| {
            allowed_origin.scheme().eq(&origin.scheme())
                && allowed_origin.host().eq(&origin.host())
                && allowed_origin.port().eq(&origin.port())
        })
    });

    CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_credentials(true)
        .allow_headers(allowed_headers)
        .allow_methods(allowed_methods)
        .expose_headers(exposed_headers)
}
