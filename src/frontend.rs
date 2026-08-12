use std::io;
use std::path::{Path, PathBuf};

use actix_files::{Files, NamedFile};
use actix_web::http::{Method, header};
use actix_web::{HttpRequest, HttpResponse, web};
use uuid::{Variant, Version};

const SPA_ROUTES: &[&str] = &[
    "/",
    "/create_scan",
    "/task",
    "/scanner",
    "/analysis",
    "/audit",
    "/open-source",
    "/testpage",
    "/setting",
    "/user/info",
    "/user/security",
];

const REQUIRED_FRONTEND_FILES: &[&str] = &["index.html", "login.html", "search.html"];

#[derive(Clone, Debug)]
pub struct FrontendAssets {
    directory: PathBuf,
}

impl FrontendAssets {
    pub fn new(directory: impl Into<PathBuf>) -> io::Result<Self> {
        let directory = directory.into();
        for file_name in REQUIRED_FRONTEND_FILES {
            let path = directory.join(file_name);
            if !path.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("缺少前端构建文件：{}", path.display()),
                ));
            }
        }

        let asset_directory = directory.join("assets");
        if !asset_directory.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("缺少前端资源目录：{}", asset_directory.display()),
            ));
        }

        Ok(Self { directory })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

pub fn assets_service(directory: impl AsRef<Path>) -> Files {
    Files::new("/assets", directory.as_ref().join("assets"))
        .use_etag(true)
        .use_last_modified(true)
        .prefer_utf8(true)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    for route in SPA_ROUTES {
        cfg.service(
            web::resource(*route)
                .route(web::get().to(spa_entry))
                .route(web::head().to(spa_entry)),
        );
    }

    cfg.service(
        web::resource("/task/{task_id}")
            .route(web::get().to(spa_entry))
            .route(web::head().to(spa_entry)),
    )
    .service(
        web::resource("/scanner/{scanner_id}")
            .route(web::get().to(spa_entry))
            .route(web::head().to(spa_entry)),
    )
    .service(
        web::resource("/login")
            .route(web::get().to(login_page))
            .route(web::head().to(login_page)),
    )
    .service(
        web::resource("/login.html")
            .route(web::get().to(login_page))
            .route(web::head().to(login_page)),
    )
    .service(
        web::resource("/search.html")
            .route(web::get().to(search_page))
            .route(web::head().to(search_page)),
    )
    .service(
        web::resource("/favicon.ico")
            .route(web::get().to(favicon))
            .route(web::head().to(favicon)),
    );
}

pub fn is_spa_path(path: &str) -> bool {
    if SPA_ROUTES.contains(&path) {
        return true;
    }

    if let Some(task_id) = single_path_parameter(path, "/task/") {
        return uuid::Uuid::parse_str(task_id)
            .map(|value| {
                value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
            })
            .unwrap_or(false);
    }

    if let Some(scanner_id) = single_path_parameter(path, "/scanner/") {
        return uuid::Uuid::parse_str(scanner_id)
            .map(|value| value.get_variant() == Variant::RFC4122)
            .unwrap_or(false);
    }

    false
}

pub fn is_protected_frontend_path(path: &str) -> bool {
    is_spa_path(path) || path == "/search.html"
}

pub fn is_frontend_resource_path(path: &str) -> bool {
    is_protected_frontend_path(path)
        || matches!(path, "/login" | "/login.html" | "/favicon.ico")
        || path.starts_with("/assets/")
}

fn single_path_parameter<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let value = path.strip_prefix(prefix)?;
    (!value.is_empty() && !value.contains('/')).then_some(value)
}

fn accepts_html(req: &HttpRequest) -> bool {
    let Some(value) = req.headers().get(header::ACCEPT) else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };

    value.split(',').any(|item| {
        matches!(
            item.trim().split(';').next().unwrap_or_default(),
            "text/html" | "text/*" | "*/*"
        )
    })
}

async fn spa_entry(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    if !is_spa_path(req.path()) {
        return Ok(HttpResponse::NotFound().finish());
    }
    html_response(&req, &assets, "index.html").await
}

async fn login_page(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    html_response(&req, &assets, "login.html").await
}

async fn search_page(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    html_response(&req, &assets, "search.html").await
}

async fn html_response(
    req: &HttpRequest,
    assets: &FrontendAssets,
    file_name: &str,
) -> actix_web::Result<HttpResponse> {
    if !accepts_html(req) {
        return Ok(HttpResponse::NotAcceptable().finish());
    }

    let file = NamedFile::open_async(assets.directory().join(file_name)).await?;
    if req.method() == Method::HEAD {
        return Ok(HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, file.content_type().to_string()))
            .insert_header((header::CONTENT_LENGTH, file.metadata().len().to_string()))
            .insert_header((header::CACHE_CONTROL, "no-cache"))
            .finish());
    }
    let mut response = file.into_response(req);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-cache"),
    );
    Ok(response)
}

async fn favicon(
    req: HttpRequest,
    assets: web::Data<FrontendAssets>,
) -> actix_web::Result<HttpResponse> {
    let file = NamedFile::open_async(assets.directory().join("favicon.ico")).await?;
    if req.method() == Method::HEAD {
        return Ok(HttpResponse::Ok()
            .insert_header((header::CONTENT_TYPE, file.content_type().to_string()))
            .insert_header((header::CONTENT_LENGTH, file.metadata().len().to_string()))
            .finish());
    }
    Ok(file.into_response(&req))
}

#[cfg(test)]
mod tests {
    use super::{
        FrontendAssets, accepts_html, assets_service, configure, is_frontend_resource_path,
        is_spa_path,
    };
    use actix_web::{App, HttpResponse, http::StatusCode, test as actix_test, web};
    use std::fs;

    fn frontend_fixture() -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "network-mapping-frontend-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(directory.join("assets")).expect("create frontend fixture");
        fs::write(directory.join("index.html"), "<main>spa entry</main>")
            .expect("write SPA fixture");
        fs::write(directory.join("login.html"), "<main>login entry</main>")
            .expect("write login fixture");
        fs::write(directory.join("search.html"), "<main>search entry</main>")
            .expect("write search fixture");
        fs::write(directory.join("assets/app.js"), "export default true")
            .expect("write asset fixture");
        directory
    }

    #[test]
    fn only_declared_paths_are_spa_routes() {
        assert!(is_spa_path("/"));
        assert!(is_spa_path("/audit"));
        assert!(is_spa_path("/task/019c0000-0000-7000-8000-000000000001"));
        assert!(is_spa_path("/scanner/019c0000-0000-4000-8000-000000000001"));

        assert!(!is_spa_path("/unknown"));
        assert!(!is_spa_path("/api/audit/events"));
        assert!(!is_spa_path("/task/not-a-uuid"));
        assert!(!is_spa_path("/task/019c0000-0000-4000-8000-000000000001"));
        assert!(!is_spa_path("/scanner/id/extra"));
        assert!(!is_spa_path(
            "/scanner/00000000-0000-0000-0000-000000000000"
        ));
    }

    #[test]
    fn frontend_resources_are_narrowly_scoped() {
        assert!(is_frontend_resource_path("/login"));
        assert!(is_frontend_resource_path("/search.html"));
        assert!(is_frontend_resource_path("/assets/app.js"));
        assert!(!is_frontend_resource_path("/api/unknown"));
        assert!(!is_frontend_resource_path("/missing.js"));
    }

    #[test]
    fn spa_document_requires_an_html_compatible_accept_header() {
        let html = actix_test::TestRequest::default()
            .insert_header(("Accept", "text/html,application/xhtml+xml"))
            .to_http_request();
        let json = actix_test::TestRequest::default()
            .insert_header(("Accept", "application/json"))
            .to_http_request();

        assert!(accepts_html(&html));
        assert!(!accepts_html(&json));
    }

    #[actix_web::test]
    async fn explicit_routes_serve_spa_without_global_fallback() {
        let directory = frontend_fixture();
        let assets = FrontendAssets::new(&directory).expect("valid frontend fixture");
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(assets))
                .configure(configure)
                .service(assets_service(&directory))
                .default_service(web::to(|| async { HttpResponse::NotFound().finish() })),
        )
        .await;

        let spa_request = actix_test::TestRequest::get()
            .uri("/audit")
            .insert_header(("Accept", "text/html"))
            .to_request();
        let spa_response = actix_test::call_service(&app, spa_request).await;
        assert_eq!(spa_response.status(), StatusCode::OK);
        assert_eq!(
            actix_test::read_body(spa_response).await,
            web::Bytes::from_static(b"<main>spa entry</main>")
        );

        let head_request = actix_test::TestRequest::default()
            .method(actix_web::http::Method::HEAD)
            .uri("/audit")
            .insert_header(("Accept", "text/html"))
            .to_request();
        let head_response = actix_test::call_service(&app, head_request).await;
        assert_eq!(head_response.status(), StatusCode::OK);
        assert!(actix_test::read_body(head_response).await.is_empty());

        let invalid_task = actix_test::TestRequest::get()
            .uri("/task/not-a-uuid")
            .insert_header(("Accept", "text/html"))
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, invalid_task).await.status(),
            StatusCode::NOT_FOUND
        );

        let unknown = actix_test::TestRequest::get()
            .uri("/not-a-frontend-route")
            .insert_header(("Accept", "text/html"))
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, unknown).await.status(),
            StatusCode::NOT_FOUND
        );

        let api_unknown = actix_test::TestRequest::get()
            .uri("/api/not-found")
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, api_unknown).await.status(),
            StatusCode::NOT_FOUND
        );

        let wrong_method = actix_test::TestRequest::post().uri("/audit").to_request();
        assert_eq!(
            actix_test::call_service(&app, wrong_method).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );

        let missing_asset = actix_test::TestRequest::get()
            .uri("/assets/missing.js")
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, missing_asset).await.status(),
            StatusCode::NOT_FOUND
        );

        fs::remove_dir_all(directory).expect("remove frontend fixture");
    }

    #[actix_web::test]
    async fn html_entry_rejects_json_only_clients() {
        let directory = frontend_fixture();
        let assets = FrontendAssets::new(&directory).expect("valid frontend fixture");
        let app = actix_test::init_service(
            App::new()
                .app_data(web::Data::new(assets))
                .configure(configure),
        )
        .await;
        let request = actix_test::TestRequest::get()
            .uri("/audit")
            .insert_header(("Accept", "application/json"))
            .to_request();

        assert_eq!(
            actix_test::call_service(&app, request).await.status(),
            StatusCode::NOT_ACCEPTABLE
        );
        fs::remove_dir_all(directory).expect("remove frontend fixture");
    }
}
