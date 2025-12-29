# XSS Scanner REST API Documentation

## Base URL

http://localhost:8000/api/v1


## Endpoints

### 1. Health Check
Insert at cursor

GET /health


**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2025-12-29T04:00:00"
}
Insert at cursor

2. XSS Scan


POST /scan/xss
Insert at cursor

Request Body:
{
  "target": "https://example.com"
}

Response:

{
  "status": "completed",
  "target": "https://example.com",
  "vulnerabilities": [...],
  "count": 2
}
Insert at cursor

3. SQL Injection Scan


POST /scan/sql
Insert at cursor

Request Body:

{
  "target": "https://example.com"
}
Insert at cursor

4. List Reports


GET /reports
Insert at cursor

Response:

{
  "reports": [
    {
      "filename": "report_123.json",
      "path": "/api/v1/reports/report_123.json"
    }
  ],
  "count": 1
}
Insert at cursor

5. Get Report


GET /reports/<filename>
Insert at cursor

Usage Examples

cURL


# Health check
curl http://localhost:8000/api/v1/health

# XSS Scan
curl -X POST http://localhost:8000/api/v1/scan/xss \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# List reports
curl http://localhost:8000/api/v1/reports
Insert at cursor

Python


import requests

# XSS Scan
response = requests.post(
    'http://localhost:8000/api/v1/scan/xss',
    json={'target': 'https://example.com'}
)
print(response.json())
Insert at cursor

