//! Search functionality for the index

use super::SearchResult;
use anyhow::Result;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Schema, Value};
use tantivy::Index;

/// Execute a search query
pub fn execute_search(
    index: &Index,
    schema: &Schema,
    query_str: &str,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let reader = index.reader()?;
    let searcher = reader.searcher();

    let path_field = schema.get_field("path").unwrap();
    let language_field = schema.get_field("language").unwrap();
    let content_field = schema.get_field("content").unwrap();
    let findings_field = schema.get_field("findings").unwrap();

    let query_parser = QueryParser::for_index(index, vec![path_field, content_field]);
    let query = query_parser.parse_query(query_str)?;

    let top_docs = searcher.search(&query, &TopDocs::with_limit(limit))?;

    let mut results = Vec::new();

    for (score, doc_address) in top_docs {
        let doc: tantivy::TantivyDocument = searcher.doc(doc_address)?;

        let path = doc
            .get_first(path_field)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let language = doc
            .get_first(language_field)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let findings_json = doc
            .get_first(findings_field)
            .and_then(|v| v.as_str())
            .unwrap_or("[]");

        let findings_count: usize = serde_json::from_str::<Vec<serde_json::Value>>(findings_json)
            .map(|v| v.len())
            .unwrap_or(0);

        results.push(SearchResult {
            path,
            language,
            score,
            findings_count,
        });
    }

    Ok(results)
}

/// Search by severity level
pub fn search_by_severity(
    index: &Index,
    schema: &Schema,
    min_severity: u8,
    limit: usize,
) -> Result<Vec<SearchResult>> {
    let reader = index.reader()?;
    let searcher = reader.searcher();

    let severity_field = schema.get_field("max_severity").unwrap();
    let path_field = schema.get_field("path").unwrap();
    let language_field = schema.get_field("language").unwrap();
    let findings_field = schema.get_field("findings").unwrap();

    // Use range query for severity - tantivy 0.22 API
    let field_name = schema.get_field_entry(severity_field).name().to_string();
    let query = tantivy::query::RangeQuery::new_i64(
        field_name,
        min_severity as i64..4, // exclusive end
    );

    let top_docs = searcher.search(&query, &TopDocs::with_limit(limit))?;

    let mut results = Vec::new();

    for (score, doc_address) in top_docs {
        let doc: tantivy::TantivyDocument = searcher.doc(doc_address)?;

        let path = doc
            .get_first(path_field)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let language = doc
            .get_first(language_field)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let findings_json = doc
            .get_first(findings_field)
            .and_then(|v| v.as_str())
            .unwrap_or("[]");

        let findings_count: usize = serde_json::from_str::<Vec<serde_json::Value>>(findings_json)
            .map(|v| v.len())
            .unwrap_or(0);

        results.push(SearchResult {
            path,
            language,
            score,
            findings_count,
        });
    }

    Ok(results)
}
