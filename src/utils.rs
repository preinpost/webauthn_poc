use actix_web::web::Data;
use webauthn_rs::prelude::Url;
use webauthn_rs::{Webauthn, WebauthnBuilder};

pub(crate) fn create_webauthn() -> Data<Webauthn> {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:8081").expect("Invalid URL");

    let builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
    let builder = builder.rp_name("Actix-web webauthn-rs");
    let webauthn = builder.build().expect("Invalid configuration");

    Data::new(webauthn)
}