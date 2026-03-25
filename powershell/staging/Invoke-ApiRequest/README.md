# Invoke-ApiRequest

General-purpose REST API client with retry logic, pagination, request timing, and response validation. Supports Bearer token, API key, and Basic auth. Useful for ad-hoc API testing, webhook integration, and scripted API workflows.

## Quick Start

```powershell
# Simple GET with Bearer token
.\Invoke-ApiRequest.ps1 -Url "https://api.example.com/v1/users" -BearerToken "eyJ..."

# POST with JSON body
.\Invoke-ApiRequest.ps1 -Method POST -Url "https://api.example.com/v1/items" -Body '{"name":"test","active":true}'

# API key authentication
.\Invoke-ApiRequest.ps1 -Url "https://api.example.com/data" -ApiKey "sk-abc123"
```

## Prerequisites

- PowerShell 5.1+
- No external modules required
- Network access to the target API

## Parameters

All parameters override their `$Config` equivalents. When using `-Url`, it replaces the `BaseUrl + Endpoint` concatenation entirely.

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Method` | `string` | HTTP method: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. Default: `GET`. |
| `-Url` | `string` | Full request URL. Bypasses `BaseUrl` + `Endpoint` when specified. |
| `-Body` | `string` | JSON string for the request body. Ignored for GET and DELETE. |
| `-BearerToken` | `string` | Bearer token placed in the `Authorization` header. |
| `-ApiKey` | `string` | API key value placed in the header specified by `$Config.ApiKeyHeader`. |
| `-BasicUser` | `string` | Username for HTTP Basic authentication. |
| `-BasicPass` | `string` | Password for HTTP Basic authentication. |

## Configuration

### Request

| Setting | Default | Description |
|---------|---------|-------------|
| `BaseUrl` | `https://api.example.com` | Base URL for the API. |
| `Endpoint` | `/v1/resource` | Path appended to `BaseUrl`. Ignored when `-Url` parameter is used. |
| `Method` | `GET` | Default HTTP method. |
| `Body` | `$null` | Default request body. Can be a hashtable (auto-serialized) or a JSON string. |

### Authentication

Three auth methods are supported. The script uses the **first non-null** method in this priority:

1. **Bearer token** — `Authorization: Bearer <token>`
2. **API key** — places the key in a configurable header (default: `X-API-Key`)
3. **Basic auth** — `Authorization: Basic <base64(user:pass)>`

Credentials can come from environment variables (preferred) or the `$Config` block:

```powershell
# Bearer (env var)
$env:API_BEARER_TOKEN = "eyJhbGci..."

# API key (env var)
$env:API_KEY = "sk-abc123"

# Basic auth (env vars)
$env:API_USER = "admin"
$env:API_PASS = "secret"
```

| Setting | Default | Description |
|---------|---------|-------------|
| `BearerToken` | `$env:API_BEARER_TOKEN` | Bearer token value. |
| `ApiKeyHeader` | `X-API-Key` | Header name for the API key. Change to match your API (e.g., `Authorization`, `X-Auth-Token`). |
| `ApiKey` | `$env:API_KEY` | API key value. |
| `BasicUser` | `$env:API_USER` | Basic auth username. |
| `BasicPass` | `$env:API_PASS` | Basic auth password. |
| `ExtraHeaders` | `@{}` | Additional headers merged into every request (e.g., `@{ "Accept" = "application/json" }`). |

### Retry Logic

| Setting | Default | Description |
|---------|---------|-------------|
| `MaxRetries` | `3` | Total attempts per request. Set to `1` to disable retry. |
| `RetryOnCodes` | `@(429, 500, 502, 503, 504)` | HTTP status codes that trigger a retry. |

Retry behavior:
- **HTTP 429** — respects the `Retry-After` header if present, otherwise waits 5 seconds
- **HTTP 5xx** — exponential backoff: 2s, 4s, 8s, ...
- **Other errors** (401, 403, 404, etc.) — fail immediately, no retry

### Pagination

| Setting | Default | Description |
|---------|---------|-------------|
| `PaginationMode` | `None` | `None`, `NextLink`, or `Offset`. |
| `NextLinkProperty` | `@odata.nextLink` | JSON property containing the next page URL. Works with Microsoft Graph, OData APIs, and any API that returns a next-page URL. |
| `OffsetPageSize` | `100` | Page size for offset-based pagination. The script appends `?offset=N&limit=M` to each request. |

#### NextLink Mode

For APIs that return a URL to the next page (Microsoft Graph, OData, many REST APIs):

```powershell
$Config.PaginationMode   = "NextLink"
$Config.NextLinkProperty = '@odata.nextLink'  # or "next", "nextPage", etc.
```

The script follows the link until the property is absent or null, accumulating all `.value` arrays.

#### Offset Mode

For APIs that use numeric offset/limit parameters:

```powershell
$Config.PaginationMode = "Offset"
$Config.OffsetPageSize = 50
```

The script increments the offset until a page returns fewer items than `OffsetPageSize`.

### Response Validation

| Setting | Default | Description |
|---------|---------|-------------|
| `ExpectedStatusCodes` | `@(200, 201, 204)` | Status codes considered successful. Others trigger a warning in the log. |

## Usage Examples

```powershell
# GET with Bearer token
.\Invoke-ApiRequest.ps1 -Url "https://graph.microsoft.com/v1.0/me" -BearerToken $token

# POST to create a resource
.\Invoke-ApiRequest.ps1 -Method POST `
    -Url "https://api.example.com/v1/tickets" `
    -Body '{"title":"Server down","priority":"high"}' `
    -ApiKey "sk-abc123"

# PUT to update
.\Invoke-ApiRequest.ps1 -Method PUT `
    -Url "https://api.example.com/v1/tickets/42" `
    -Body '{"status":"resolved"}' `
    -BearerToken $token

# DELETE
.\Invoke-ApiRequest.ps1 -Method DELETE `
    -Url "https://api.example.com/v1/tickets/42" `
    -BearerToken $token

# Basic auth against a legacy API
.\Invoke-ApiRequest.ps1 -Url "https://legacy.internal/api/health" `
    -BasicUser "admin" -BasicPass "password"

# Paginated Graph API call (edit $Config for pagination mode)
# Set $Config.PaginationMode = "NextLink" in the script, then:
.\Invoke-ApiRequest.ps1 -Url "https://graph.microsoft.com/v1.0/users?`$top=100" `
    -BearerToken $token
```

## Output

### JSON Response File

`output\response_<yyyyMMdd_HHmmss>.json`

The full response body (or accumulated paginated results) saved as JSON. Set `$Config.OutputDir = $null` to skip saving.

### Console Summary

Sections:
- **Request** — method, URL, auth type, pagination mode
- **Response** — HTTP status code (color-coded: green = expected, yellow = unexpected, red = error), request count, total time, average time per request, response size in bytes
- **Response body** — first 20 lines of the formatted JSON, with a count of remaining lines

### Log

`logs\Invoke-ApiRequest_<yyyyMMdd_HHmmss>.log`

Per-request details including status code, elapsed time, and response size.

## Request Timing

Every request is timed using `System.Diagnostics.Stopwatch`. The console summary shows:
- **Total time** — sum of all request durations (including paginated requests)
- **Average time** — total / request count
- **Per-request** — logged individually in the log file

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All requests completed successfully |
| `1` | One or more requests failed after all retries, or a fatal error occurred |

## Common Patterns

### FortiGate API

```powershell
.\Invoke-ApiRequest.ps1 `
    -Url "https://firewall.corp.local/api/v2/cmdb/firewall/policy" `
    -BearerToken $fortigateToken
```

### ServiceNow

```powershell
.\Invoke-ApiRequest.ps1 `
    -Url "https://instance.service-now.com/api/now/table/incident?sysparm_limit=10" `
    -BasicUser "api_user" -BasicPass "api_pass"
```

### Webhook / Notification

```powershell
.\Invoke-ApiRequest.ps1 -Method POST `
    -Url "https://hooks.slack.com/services/T00/B00/xxx" `
    -Body '{"text":"Deployment complete"}'
```
