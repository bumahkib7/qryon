# HTTP API Reference

RMA provides an HTTP API through daemon mode for IDE integration and programmatic access.

## Starting the Server

```bash
# Default: http://127.0.0.1:9876
rma daemon

# Custom host and port
rma daemon --host 0.0.0.0 --port 8080
```

## Base URL

```
http://localhost:9876
```

## Authentication

Currently, the API does not require authentication. It is designed for local use only.
For production deployments, place behind a reverse proxy with authentication.

## Endpoints

### Health Check

Check if the server is running.

```
GET /health
```

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime_seconds": 3600
}
```

### Scan Directory

Scan a directory for security issues and code metrics.

```
POST /api/v1/scan
```

**Request Body:**
```json
{
  "path": "/path/to/repository",
  "languages": ["rust", "python"],
  "severity": "warning",
  "incremental": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| path | string | yes | Absolute path to scan |
| languages | string[] | no | Languages to scan (default: all) |
| severity | string | no | Minimum severity: info, warning, error, critical |
| incremental | boolean | no | Only scan changed files |

**Response:**
```json
{
  "status": "success",
  "scan_id": "abc123",
  "duration_ms": 1500,
  "summary": {
    "files_scanned": 150,
    "total_findings": 25,
    "by_severity": {
      "critical": 2,
      "error": 5,
      "warning": 10,
      "info": 8
    }
  },
  "findings": [
    {
      "rule_id": "rust/unsafe-block",
      "severity": "warning",
      "message": "Unsafe block detected",
      "file": "src/lib.rs",
      "line": 42,
      "column": 5,
      "snippet": "unsafe { ... }"
    }
  ]
}
```

### Analyze Single File

Analyze a single file.

```
POST /api/v1/analyze
```

**Request Body:**
```json
{
  "path": "/path/to/file.rs"
}
```

Or with inline content:

```json
{
  "filename": "example.rs",
  "content": "fn main() { let x = unsafe { ... }; }",
  "language": "rust"
}
```

**Response:**
```json
{
  "status": "success",
  "file": "example.rs",
  "language": "rust",
  "metrics": {
    "lines": 42,
    "functions": 5,
    "cyclomatic_complexity": 8
  },
  "findings": [
    {
      "rule_id": "rust/unsafe-block",
      "severity": "warning",
      "message": "Unsafe block detected",
      "line": 1,
      "column": 20
    }
  ]
}
```

### Search Index

Search the code index.

```
GET /api/v1/search?q=<query>&type=<type>&limit=<n>
```

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| q | string | yes | Search query |
| type | string | no | Search type: content, file, finding (default: content) |
| limit | number | no | Max results (default: 20) |

**Response:**
```json
{
  "status": "success",
  "query": "TODO",
  "type": "content",
  "total_hits": 15,
  "results": [
    {
      "file": "src/main.rs",
      "line": 10,
      "content": "// TODO: implement error handling",
      "score": 1.5
    }
  ]
}
```

### Get Statistics

Get index and daemon statistics.

```
GET /api/v1/stats
```

**Response:**
```json
{
  "status": "success",
  "index": {
    "total_files": 500,
    "total_lines": 50000,
    "by_language": {
      "rust": 200,
      "python": 150,
      "javascript": 150
    },
    "index_size_bytes": 10485760,
    "last_indexed": "2024-01-15T10:30:00Z"
  },
  "daemon": {
    "uptime_seconds": 3600,
    "requests_served": 150,
    "scans_completed": 25
  }
}
```

### Trigger Re-index

Force a re-index of the repository.

```
POST /api/v1/index
```

**Request Body:**
```json
{
  "path": "/path/to/repository",
  "force": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| path | string | yes | Path to index |
| force | boolean | no | Force full re-index |

**Response:**
```json
{
  "status": "success",
  "message": "Indexing started",
  "job_id": "idx-123"
}
```

### Get Index Job Status

Check status of an indexing job.

```
GET /api/v1/index/<job_id>
```

**Response:**
```json
{
  "status": "success",
  "job_id": "idx-123",
  "state": "completed",
  "files_indexed": 500,
  "duration_ms": 5000
}
```

## Error Responses

All endpoints return errors in this format:

```json
{
  "status": "error",
  "code": "INVALID_PATH",
  "message": "The specified path does not exist",
  "details": {
    "path": "/nonexistent/path"
  }
}
```

**Error Codes:**
| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_REQUEST | 400 | Malformed request body |
| INVALID_PATH | 400 | Path does not exist |
| INVALID_LANGUAGE | 400 | Unknown language specified |
| NOT_FOUND | 404 | Resource not found |
| SCAN_FAILED | 500 | Scan encountered an error |
| INDEX_FAILED | 500 | Indexing encountered an error |
| INTERNAL_ERROR | 500 | Unexpected server error |

## Rate Limiting

The daemon does not implement rate limiting. For production use, place behind a reverse proxy.

## CORS

CORS is enabled by default, allowing requests from any origin. Configure via environment:

```bash
RMA_CORS_ORIGINS=http://localhost:3000 rma daemon
```

## WebSocket (Future)

A WebSocket endpoint for real-time updates is planned:

```
WS /api/v1/watch
```

## Example: cURL

```bash
# Health check
curl http://localhost:9876/health

# Scan a directory
curl -X POST http://localhost:9876/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/home/user/project"}'

# Search
curl "http://localhost:9876/api/v1/search?q=TODO&limit=10"

# Analyze inline code
curl -X POST http://localhost:9876/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "test.rs",
    "content": "fn main() { unsafe { } }",
    "language": "rust"
  }'
```

## Example: Python

```python
import requests

BASE_URL = "http://localhost:9876"

# Scan
response = requests.post(f"{BASE_URL}/api/v1/scan", json={
    "path": "/path/to/project",
    "severity": "warning"
})
results = response.json()
print(f"Found {results['summary']['total_findings']} issues")

# Search
response = requests.get(f"{BASE_URL}/api/v1/search", params={
    "q": "TODO",
    "type": "content"
})
for result in response.json()["results"]:
    print(f"{result['file']}:{result['line']}: {result['content']}")
```

## Example: JavaScript

```javascript
const BASE_URL = 'http://localhost:9876';

// Scan
const scanResponse = await fetch(`${BASE_URL}/api/v1/scan`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    path: '/path/to/project',
    severity: 'warning'
  })
});
const results = await scanResponse.json();
console.log(`Found ${results.summary.total_findings} issues`);

// Search
const searchResponse = await fetch(
  `${BASE_URL}/api/v1/search?q=TODO&type=content`
);
const searchResults = await searchResponse.json();
searchResults.results.forEach(r => {
  console.log(`${r.file}:${r.line}: ${r.content}`);
});
```
