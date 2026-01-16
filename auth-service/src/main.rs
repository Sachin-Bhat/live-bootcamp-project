use axum::{Router, extract::Query, response::Html, routing::get, serve};
use serde::Deserialize;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let assets_dir = ServeDir::new("assets");
    let app = Router::new()
        .fallback_service(assets_dir)
        .route("/hello", get(hello_handler));

    // Here we are using ip 0.0.0.0 so the service is listening on all the configured network interfaces.
    // This is needed for Docker to work, which we will add later on.
    // See: https://stackoverflow.com/questions/39525820/docker-port-forwarding-not-working
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct HelloQuery {
    name: Option<String>,
}

async fn hello_handler(Query(query): Query<HelloQuery>) -> Html<String> {
    let name = query.name.as_deref().unwrap_or("friend");
    let name = escape_html(name);
    Html(format!("<h1>Hello, {}!</h1>", name))
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}
