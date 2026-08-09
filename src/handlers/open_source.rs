use actix_web::{HttpResponse, Responder, get, web};
use serde::Serialize;

use crate::open_source::{OpenSourceCatalog, OpenSourceProject};

#[derive(Serialize)]
struct OpenSourceResponse<'a> {
    last_reviewed: &'a str,
    total: usize,
    projects: &'a [OpenSourceProject],
}

#[get("/api/open-source/projects")]
pub async fn get_open_source_projects(catalog: web::Data<OpenSourceCatalog>) -> impl Responder {
    HttpResponse::Ok().json(OpenSourceResponse {
        last_reviewed: &catalog.last_reviewed,
        total: catalog.total(),
        projects: &catalog.projects,
    })
}

#[cfg(test)]
mod tests {
    use super::get_open_source_projects;
    use crate::open_source::OpenSourceCatalog;
    use actix_web::{App, http::StatusCode, test, web};

    #[actix_web::test]
    async fn endpoint_returns_embedded_catalog() {
        let catalog = OpenSourceCatalog::from_embedded().expect("catalog must load");
        let expected_total = catalog.total();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(catalog))
                .service(get_open_source_projects),
        )
        .await;

        let request = test::TestRequest::get()
            .uri("/api/open-source/projects")
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["total"].as_u64(), Some(expected_total as u64));
        assert_eq!(
            body["projects"].as_array().map(Vec::len),
            Some(expected_total)
        );
    }
}
