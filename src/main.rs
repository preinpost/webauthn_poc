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
use sqlx::{Executor, FromRow, Pool, Sqlite};
use sqlx::sqlite::SqlitePoolOptions;
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
async fn member_register(
    req: Json<RegisterPublicKeyCredential>,
    webauthn: Data<Webauthn>,
    session: Session,
    pool: Data<Pool<Sqlite>>
) -> HttpResponse {
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

    let ser = general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&sk).unwrap());
    info!("ser = {:?}", &ser);

    let cnt = sqlx::query("INSERT INTO users (user_id, name, passkey) VALUES ($1, $2, $3)")
        .bind("user1")
        .bind("John Doe")
        .bind(ser)
        .execute(pool.get_ref()).await.unwrap();

    info!("cnt = {:?}", cnt);

    session.insert("key", sk.clone());

    HttpResponse::Ok().finish()
}

#[get("get_login_challenge")]
async fn get_login_challenge(webauthn: Data<Webauthn>, session: Session, pool: Data<Pool<Sqlite>>) -> Json<RequestChallengeResponse> {

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE user_id = 'user1'")
        .fetch_one(pool.get_ref()).await.unwrap();

    info!("user.user_id = {:?}", user.user_id);
    info!("user.passkey = {:?}", user.passkey);

    let passkey = general_purpose::URL_SAFE_NO_PAD.decode(user.passkey.as_bytes()).unwrap();
    info!("passkey = {:?}", passkey);
    let passkey: Passkey = serde_json::from_str(String::from_utf8(passkey).unwrap().as_str()).unwrap();

    let (rcr, auth_state) = webauthn.start_passkey_authentication(&*vec![passkey])
        .expect("Failed to start login.");

    session.insert("auth_state", auth_state).expect("fail to insert auth_state");

    Json(rcr)
}

#[post("member_login")]
async fn member_login(
    req: Json<PublicKeyCredential>,
    webauthn: Data<Webauthn>,
    session: Session,
    pool: Data<Pool<Sqlite>>
) -> impl Responder {

    let auth_state = session.get::<PasskeyAuthentication>("auth_state").unwrap().unwrap();

    let auth_result = webauthn
        .finish_passkey_authentication(&req, &auth_state)
        .map_err(|e| {
            info!("challenge_register -> {:?}", e);
            return HttpResponse::BadRequest().finish();
        })
        .expect("error");


    info!("Authentication Successful!");


    HttpResponse::Ok().body("member_login")
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

    let pool = sqlx_sqlite_init().await.unwrap();

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
            .app_data(Data::new(pool.clone()).clone())
            .service(
                web::scope("/login")
                    .service(web_idx)
                    .service(get_challenge)
                    .service(member_register)
                    .service(get_login_challenge)
                    .service(member_login)
            )
        // .service(web::resource("/web/{resource_path}").route(web::get().to(get_htmx)))
    })
        .bind(("0.0.0.0", 8081))
        .expect("Failed to start")
        .run()
        .await
        .unwrap();
}


async fn sqlx_sqlite_init() -> sqlx::Result<(Pool<Sqlite>)> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:").await?;

    // create users table
    sqlx::query("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            passkey TEXT NULLABLE
        )").execute(&pool).await?;

    Ok(pool)
}

#[derive(Debug, FromRow)]
pub struct User {
    pub id: i64,
    pub user_id: String,
    pub name: String,
    pub passkey: String
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