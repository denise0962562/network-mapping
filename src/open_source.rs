use serde::{Deserialize, Serialize};

const EMBEDDED_CATALOG: &str = include_str!("../source/open_source_projects.json");

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenSourceProject {
    pub name: String,
    pub package: String,
    pub version: String,
    pub license: String,
    pub ecosystem: String,
    pub usage: String,
    pub homepage: String,
    pub repository: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenSourceCatalog {
    pub last_reviewed: String,
    pub projects: Vec<OpenSourceProject>,
}

impl OpenSourceCatalog {
    pub fn from_embedded() -> Result<Self, serde_json::Error> {
        serde_json::from_str(EMBEDDED_CATALOG)
    }

    pub fn total(&self) -> usize {
        self.projects.len()
    }
}

#[cfg(test)]
mod tests {
    use super::OpenSourceCatalog;

    #[test]
    fn embedded_catalog_is_valid_and_not_empty() {
        let catalog = OpenSourceCatalog::from_embedded().expect("catalog must be valid JSON");

        assert!(!catalog.last_reviewed.is_empty());
        assert!(catalog.total() >= 10);
        assert!(catalog.projects.iter().all(|project| {
            !project.name.is_empty()
                && !project.version.is_empty()
                && !project.license.is_empty()
                && project.repository.starts_with("https://")
        }));
    }
}
