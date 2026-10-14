fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&network_mapping_server::open_api::openapi_document())
            .unwrap()
    );
}
