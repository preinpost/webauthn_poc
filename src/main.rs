use std::collections::HashMap;
use std::sync::Mutex;

use actix_files::NamedFile;
use actix_session::{Session, SessionMiddleware};
use actix_session::storage::CookieSessionStore;
use actix_web::{App, Error, get, HttpRequest, HttpResponse, HttpServer, post, Responder, web};
use actix_web::cookie::Key;
use actix_web::middleware::Logger;
use actix_web::web::{Bytes, Data, Json, JsonConfig};
use base64::Engine;
use base64::engine::general_purpose;
use log::info;
use ring::rand::{SecureRandom, SystemRandom};
use webauthn_rs::prelude::*;

use crate::session::MemorySession;
use crate::utils::create_webauthn;

mod utils;
mod session;

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[get("/{path1}")]
async fn test(path1: web::Path<String>) -> impl Responder {
    let info = path1.into_inner();
    println!("{:?}", info);
    HttpResponse::Ok().body("req_body")
}

#[get("/get_key")]
async fn get_rand_key() -> impl Responder {
    HttpResponse::Ok().body(generate_rand())
}

#[get("")]
async fn web_idx(req: HttpRequest, session: Session) -> impl Responder {
    NamedFile::open_async("./htmx/index.html").await.unwrap().respond_to(&req)
}

#[get("get_challenge")]
async fn get_challenge(webauthn: Data<Webauthn>, session: Session) -> Json<CreationChallengeResponse> {

    session.remove("reg_state");

    let user_unique_id = Uuid::new_v4();

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_unique_id,
            "claire",
            "Claire",
            None, // No other credentials are registered yet.
        )
        .expect("Failed to start registration.");

    info!("before reg_state {:?}", &reg_state);
    session.insert("reg_state", reg_state).expect("fail to insert reg_state");
    info!("Registration Challenge: {:?}", ccr);

    Json(ccr)
}

#[post("member_register")]
async fn member_register(req: Json<RegisterPublicKeyCredential>, webauthn: Data<Webauthn>, session: Session) -> HttpResponse {
    // info!("req = {:?}", &req);
    let reg_state = session.get::<PasskeyRegistration>("reg_state").unwrap().unwrap();
    // info!("after reg_state = {:?}", &reg_state);

    let sk = webauthn
        .finish_passkey_registration(&req, &reg_state)
        .map_err(|e| {
            info!("challenge_register -> {:?}", e);
            return HttpResponse::BadRequest().finish();
        })
        .expect("error");

    session.insert("key", sk.clone());

    HttpResponse::Ok().finish()
}

async fn get_htmx(req: HttpRequest, resource_path: web::Path<String>) -> HttpResponse {
    println!("{}", resource_path);

    if let Ok(readHTML) = NamedFile::open_async(format!("./htmx/{}.html", resource_path)).await {
        readHTML.respond_to(&req)
    } else {
        HttpResponse::NotFound().body("404")
    }
}


fn generate_rand() -> String {
    let mut rand_key = vec![0; 64];

    let rand = SystemRandom::new();
    rand.fill(&mut rand_key).unwrap();
    general_purpose::STANDARD_NO_PAD.encode(&rand_key)[..64].to_string()
}

#[actix_web::main]
async fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    // Initialize env-logger
    env_logger::init();

    type UserData = HashMap<String, String>;
    let webauthn_users = Data::new(Mutex::new(UserData::new()));

    // cookie key
    let key = Key::generate();

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), key.clone())
                    .cookie_name("RSSESSIONID".to_string())
                    .cookie_http_only(true)
                    .cookie_secure(false)
                    .build()
            )
            .app_data(JsonConfig::default())
            .app_data(create_webauthn())
            .app_data(webauthn_users.clone())
            .service(
                web::scope("/login")
                    .service(web_idx)
                    .service(get_challenge)
                    .service(member_register)
            )
        // .service(web::resource("/web/{resource_path}").route(web::get().to(get_htmx)))
    })
        .bind(("0.0.0.0", 8081))
        .expect("Failed to start")
        .run()
        .await
        .unwrap();
}

#[cfg(test)]
mod tests {
    use base64::{alphabet, Engine};
    use base64::engine;
    use base64::engine::general_purpose;
    use rand::Rng;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::{KeyPair, RsaKeyPair};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    #[test]
    fn test_ring() {
        let mut nonce = vec![0; 64];

        let rand = SystemRandom::new();
        rand.fill(&mut nonce).unwrap();

        println!("{:?}", &nonce);

        let nonce_ascii: String = nonce.iter().map(|&byte| byte as char).collect();
        println!("Nonce as ASCII: {}", nonce_ascii);

        let nonce_base64 = general_purpose::STANDARD_NO_PAD.encode(&nonce);
        println!("Nonce as Base64: {}", &nonce_base64[..64]);
    }

    #[test]
    fn test_generate_key_fair() {
        let key_size = 2048;

        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), key_size).expect("Failed to generate private key");

        println!("{:?}", private_key);

        let public_key: RsaPublicKey = private_key.clone().into();
        println!("{:?}", public_key);
    }

    #[test]
    fn read_private_key() {
        let pkcs8_bytes = include_bytes!("../passkey_test.pk8");
        let key_pair = RsaKeyPair::from_pkcs8(pkcs8_bytes).expect("Failed to parse PKCS#8 key");

        // 공개 키 가져오기
        let public_key_bytes = key_pair.public_key().as_ref();
        let public_key_base64 = general_purpose::STANDARD_NO_PAD.encode(key_pair.public_key().as_ref());

        // println!("Public Key: {:?}", public_key_bytes);

        println!("Public Key BASE64: {:?}", public_key_base64);
    }


    #[test]
    fn test_sign() {
        let pkcs8_bytes = include_bytes!("../passkey_test.pk8");
        let key_pair = RsaKeyPair::from_pkcs8(pkcs8_bytes).expect("Failed to parse PKCS#8 key");

        // 키 쌍 생성
        let rng = SystemRandom::new();

        // 메시지
        let message = b"Hello, World!";

        // 서명 생성
        let mut signature = vec![0; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &rng,
                message,
                &mut signature,
            )
            .expect("서명 생성 실패");

        let public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, pkcs8_bytes);

        let result = public_key.verify(message, &signature).is_ok();
        println!("result = {}", result);
    }

    #[test]
    fn generate_challenge_test() {
        const CHALLENGE_SIZE_BYTES: usize = 32;

        let mut rng = rand::thread_rng();
        let challenge = rng.gen::<[u8; CHALLENGE_SIZE_BYTES]>().to_vec();
        println!("{challenge:?}");
        println!("challenge length :  {}", challenge.len());

        const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
        let encoded_msg = CUSTOM_ENGINE.encode(&challenge);

        println!("encoded_msg : {}", &encoded_msg);
    }
}