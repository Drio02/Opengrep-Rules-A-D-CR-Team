use axum::extract::{Json, Path, Query};
use axum::response::{Html, Redirect};
use std::collections::HashMap;
use std::process::Command;

async fn get_note(Path(id): Path<String>, pool: State<PgPool>) -> String {
    let q = format!("SELECT body FROM notes WHERE id = '{}'", id);
    // ruleid: rust-taint-sqli
    let row = sqlx::query(&q).fetch_one(&pool).await.unwrap();
    // ok: rust-taint-sqli
    let row2 = sqlx::query("SELECT body FROM notes WHERE id = $1").bind(&id).fetch_one(&pool).await.unwrap();
    row.get(0)
}

async fn ping(Query(params): Query<HashMap<String, String>>) -> String {
    let host = params.get("host").unwrap();
    // ruleid: rust-taint-command-injection
    let out = Command::new("sh").arg("-c").arg(format!("ping -c 1 {}", host)).output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

async fn download(Path(name): Path<String>) -> Vec<u8> {
    let base = std::path::Path::new("/srv/files");
    // ruleid: rust-taint-path-traversal
    let p = base.join(&name);
    // ruleid: rust-taint-path-traversal
    std::fs::read(p).unwrap()
}

async fn fetch(Query(q): Query<FetchReq>) -> String {
    // ruleid: rust-taint-ssrf
    reqwest::get(&q.url).await.unwrap().text().await.unwrap()
}

async fn preview(Json(body): Json<Preview>) -> String {
    // ruleid: rust-taint-ssti
    Tera::one_off(&body.template, &Context::new(), true).unwrap()
}

async fn hello(Query(q): Query<Hello>) -> Html<String> {
    // ruleid: rust-taint-xss
    Html(format!("<h1>Hello {}</h1>", q.name))
}

async fn hello_safe(Query(q): Query<Hello>) -> Html<String> {
    // ok: rust-taint-xss
    Html(format!("<h1>Hello {}</h1>", html_escape::encode_text(&q.name)))
}

async fn go(Query(q): Query<Next>) -> Redirect {
    // ruleid: rust-taint-open-redirect
    Redirect::to(&q.next)
}
