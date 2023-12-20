use actix_files::NamedFile;
use actix_web::{App, get, HttpRequest, HttpResponse, HttpServer, post, Responder, web};

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

#[get("")]
async fn web_idx(req: HttpRequest) -> impl Responder {
    NamedFile::open_async("./htmx/index.html").await.unwrap().respond_to(&req)
}

async fn get_htmx(req: HttpRequest, resource_path: web::Path<String>) -> HttpResponse {
    println!("{}", resource_path);

    if let Ok(readHTML) = NamedFile::open_async(format!("./htmx/{}.html", resource_path)).await {
        readHTML.respond_to(&req)
    } else {
        HttpResponse::NotFound().body("404")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(echo)
            .service(
                web::scope("/login")
                    .service(web_idx)
            )
            // .service(web::resource("/web/{resource_path}").route(web::get().to(get_htmx)))
    })
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}