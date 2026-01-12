# DDNS Gateway

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

DDNS Gateway is a DDNS update service designed for RouterOS, implemented with a fully asynchronous architecture.

This service acts as a middleware, receiving HTTP update requests from RouterOS and calling the APIs of various DNS providers to query and update DNS records.

## 1. Supported Service Providers

| Provider       | Authentication Method           | Record Comment | Remarks                                                                        |
|:---------------|:--------------------------------|:---------------|:-------------------------------------------------------------------------------|
| Cloudflare     | API Token                       | Supported      | **Global API Key is NOT supported**                                            |
| Aliyun DNS     | AccessKey ID + AccessKey Secret | Supported      |                                                                                |
| Tencent DNSPod | SecretId + SecretKey            | Supported      | **Only supports Mainland China edition**, not International (`api.dnspod.com`) |

## 2. Installation

### 2.1. Install with UV (Recommended)

```bash
# Clone the repository
$ git clone https://github.com/yourusername/DDNS-Gateway.git
$ cd DDNS-Gateway

# Create virtual environment, install dependencies
$ uv sync

# Run (choose one)
$ uv run ddns-gateway
$ ./.venv/bin/ddns-gateway

INFO:     Started server process [37951]
INFO:     Waiting for application startup.
2026-01-12 03:58:51 INFO  [ddns_gateway.server] DDNS Gateway starting on "0.0.0.0:38080" (Methods: GET, POST).
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:38080 (Press CTRL+C to quit)
```

### 2.2. Install with pip

> Note: Ensure Python version is at least 3.12.

```bash
pip install -e .

ddns-gateway
```

## 3. Configuration

Configuration priority:

1. Command line arguments (highest)
2. Configuration file
3. Default values (lowest)

### 3.1. Command Line Arguments

```bash
# Basic usage
uv run ddns-gateway --help
uv run ddns-gateway --config /path/to/config.toml
uv run ddns-gateway --host 127.0.0.1 --port 9000
uv run ddns-gateway --log-level DEBUG

# Output logs to file (Note: log rotation must be handled manually)
uv run ddns-gateway --log-file-enabled --log-file-path "~/log/ddns-gateway.log"
uv run ddns-gateway --log-file-disabled

# Disable authentication
uv run ddns-gateway --auth-disabled

# Enable authentication and specify tokens
uv run ddns-gateway --auth-enabled --auth-tokens tk1 tk2                # Space-separated
uv run ddns-gateway --auth-enabled --auth-tokens tk1 --auth-tokens tk1  # Specify multiple times

# Specify HTTP methods (comma-separated)
uv run ddns-gateway --methods "get,post"  # Enable GET and POST methods
uv run ddns-gateway --methods post        # Enable only POST method
```

Detailed parameter description:

| Argument                                      | Function                          | Description                                                                    |
|:----------------------------------------------|:----------------------------------|:-------------------------------------------------------------------------------|
| `--config`                                    | Specify config file path          |                                                                                |
| `--host`                                      | Listen address                    |                                                                                |
| `--port`                                      | Listen port                       |                                                                                |
| `--log-level`                                 | Log level                         |                                                                                |
| `--auth-enabled`<br>`--auth-disabled`         | Enable/disable server auth        | Mutually exclusive, cannot be specified together                               |
| `--auth-tokens`                               | Authentication token list         | Multiple tokens can be space-separated or specified multiple times (see above) |
| `--methods`                                   | Enabled HTTP methods              | Comma-separated (see above)                                                    |
| `--log-file-enabled`<br>`--log-file-disabled` | Enable/disable file logging       | Mutually exclusive, cannot be specified together                               |
| `--log-file-path`                             | Log file path                     | Ensure proper permissions, handle log rotation manually                        |
| `--health-enabled`<br>`--health-disabled`     | Enable/disable `/health` endpoint | Mutually exclusive, cannot be specified together                               |

### 3.2. Configuration File

The configuration file uses TOML format, default path is `config.toml` in this directory.

You can specify the configuration file path with the `--config` argument, e.g. `--config /path/to/config.toml`.

Configuration file format and **default values**:

```toml
[server]
host = "0.0.0.0"     # Listen address. If using Nginx as reverse proxy, set to "127.0.0.1"
port = 38080         # Listen port

[auth]
enabled = false      # Enable authentication. If enabled, requests must include a valid token. Requests without token or with invalid token will return 401 / 403 error.
tokens = []          # If authentication is enabled, configure valid tokens here. If authentication is enabled and this list is empty, all requests will be rejected.

[methods]
get_enabled = true   # Enable GET /update endpoint. If disabled, requests will return 405 Method Not Allowed.
post_enabled = true  # Enable POST /update endpoint. If disabled, requests will return 405 Method Not Allowed. Note: At least one of get_enabled or post_enabled must be true.

[logging]
level = "INFO"                           # Log level. Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
file_enabled = false                     # Enable file logging
file_path = "/var/log/ddns-gateway.log"  # Log file path. Note: ensure proper permissions, handle log rotation manually.

[health]
enabled = false                          # Enable "/health" endpoint
```

The configuration file will be type-checked. If the type is incorrect and cannot be automatically converted, the program will report an error and exit at startup.

> Note: Some types support automatic conversion (e.g. `"8080"` → `8080`, `"true"` / `"yes"` → `true`), but values that cannot be converted will still cause errors.

Expected types for each configuration item:

| Config Item            | Expected Type |
|:-----------------------|:--------------|
| `server.host`          | `str`         |
| `server.port`          | `int`         |
| `auth.enabled`         | `bool`        |
| `auth.tokens`          | `list[str]`   |
| `methods.get_enabled`  | `bool`        |
| `methods.post_enabled` | `bool`        |
| `logging.level`        | `str`         |
| `logging.file_enabled` | `bool`        |
| `logging.file_path`    | `str`         |
| `health.enabled`       | `bool`        |

## 4. API Reference

### 4.1. `/update`

Supports `GET` / `POST` methods (unless a method is disabled in the configuration file), used to update DNS records.

#### 4.1.1. Request Parameters

1. Query / Body parameters

    - **GET Requests**: Parameters are passed via Query String
    - **POST Requests**: Parameters are passed via JSON Body (Content-Type: `application/json`)

    | Parameter  | Required | Description                                                                                             |
    |------------|----------|---------------------------------------------------------------------------------------------------------|
    | `provider` | Yes      | DNS provider. Options: `cloudflare`, `aliyun`, `tencent`                                                |
    | `zone`     | Yes      | DNS zone (main domain), e.g. `example.com`                                                              |
    | `record`   | Yes      | Host record name, e.g. `home`, `@`, `www`                                                               |
    | `type`     | Yes      | Record type, options: `A`, `AAAA`, `CNAME`, `TXT`                                                       |
    | `value`    | Yes      | Record value (IP address, target domain or text)                                                        |
    | `ttl`      | No       | TTL (seconds). If not provided, uses provider default for new records, keeps existing value for updates |
    | `comment`  | No       | DNS record comment                                                                                      |

    Tencent Cloud / Aliyun default TTL is 600 seconds; Cloudflare default is Auto, currently 300 seconds.

    Note: TTL must not be lower than the minimum allowed by the account, otherwise it will fail. Currently for Cloudflare non-Enterprise accounts, min TTL is 60 seconds, max is 1 day.

    > See [Cloudflare: Time to Live (TTL)](https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/).

2. HTTP Headers

    | Header                     | Required    | Description                                         |
    |:---------------------------|:------------|:----------------------------------------------------|
    | `Authorization`            | Conditional | `Bearer <token>` format (if server auth is enabled) |
    | `X-Upstream-Authorization` | Yes         | DNS provider credentials, format below              |

3. DNS Provider Credential Format

    The `X-Upstream-Authorization` header uses the `ApiKey` scheme:

    ```
    ApiKey id="<ID>", secret="<SECRET>"
    ```

    - **Cloudflare**: Only `secret` (API Token) is needed, `id` can be omitted
      - Example: `ApiKey secret="cf-token-xxx"`
    - **Aliyun**: Requires both `id` (AccessKey ID) and `secret` (AccessKey Secret)
      - Example: `ApiKey id="LTAI4xxx", secret="xxxxx"`
    - **Tencent**: Requires both `id` (SecretId) and `secret` (SecretKey)
      - Example: `ApiKey id="AKIDxxx", secret="xxxxx"`

    > **Note**: If `id` is provided for Cloudflare, it will be ignored.

#### 4.1.2. Response Example

```json
{
  "status": "success",
  "code": 200,
  "message": "DNS record updated successfully",
  "action": "updated",
  "data": {
    "provider": "cloudflare",
    "zone": "example.com",
    "record": "home",
    "fqdn": "home.example.com",
    "type": "A",
    "value": "1.2.3.4",
    "ttl": 600,
    "previous_value": "5.6.7.8"
  },
  "provider_metadata": {
    "record_id": "abc123",
    "request_id": "xyz789",
    "zone_id": "zone123"
  },
  "warnings": []
}
```

### 4.2. `/health`

> **Note**: This endpoint is **disabled by default** and must be enabled via configuration file or command line arguments. This endpoint is **not affected by authentication settings**.

Supports `GET` method, used for load balancer health checks or service monitoring.

Response example: `{"status": "ok"}` / `{"detail":"Not Found"}` (when disabled).

### 4.3. Request Examples

```bash
# Cloudflare
curl "http://localhost:38080/update?provider=cloudflare&zone=example.com&record=home&type=A&value=1.2.3.4&ttl=600&comment=Hello%20World" \
  -H "Authorization: Bearer YOUR_SERVER_TOKEN" \
  -H 'X-Upstream-Authorization: ApiKey secret="YOUR_CF_TOKEN"'

# Cloudflare (POST, application/json)

curl -X POST "http://localhost:38080/update" \
  -H "Authorization: Bearer YOUR_SERVER_TOKEN" \
  -H 'X-Upstream-Authorization: ApiKey secret="YOUR_CF_TOKEN"' \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "cloudflare",
    "zone": "example.com",
    "record": "home",
    "type": "A",
    "value": "1.2.3.4",
    "ttl": 600,
    "comment": "Hello World"
  }'

# Aliyun

curl "http://localhost:38080/update?provider=aliyun&zone=example.com&record=home&type=A&value=1.2.3.4&ttl=600&comment=Hello%20World" \
  -H "Authorization: Bearer YOUR_SERVER_TOKEN" \
  -H 'X-Upstream-Authorization: ApiKey id="YOUR_ACCESS_KEY_ID", secret="YOUR_ACCESS_KEY_SECRET"'

# Tencent

curl "http://localhost:38080/update?provider=tencent&zone=example.com&record=home&type=A&value=1.2.3.4&ttl=600&comment=Hello%20World" \
  -H "Authorization: Bearer YOUR_SERVER_TOKEN" \
  -H 'X-Upstream-Authorization: ApiKey id="YOUR_SECRET_ID", secret="YOUR_SECRET_KEY"'

# Health check

curl "http://localhost:38080/health"
```

### 4.4. Response Example

```json
{
  "status": "success",
  "code": 200,
  "message": "DNS record updated successfully",
  "action": "updated",
  "data": {
    "provider": "cloudflare",
    "zone": "example.com",
    "record": "home",
    "fqdn": "home.example.com",
    "type": "A",
    "value": "1.2.3.4",
    "ttl": 600,
    "previous_value": "5.6.7.8"
  },
  "provider_metadata": {
    "record_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "zone_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "extra": {
      "cf_ray": "xxxxxxxxxxxxxxxx-TPE"
    }
  },
  "warnings": []
}
```

When server token authentication fails (401 / 403) or the request method is disabled (405), the API will return a JSON error message. For example:

- Missing Token (401):

    ```json
    {
    "status": "error",
    "code": 401,
    "message": "Missing authentication token"
    }
    ```

- Invalid Token (403):

    ```json
    {
    "status": "error",
    "code": 403,
    "message": "Invalid authentication token"
    }
    ```

- Method Not Allowed (405):

    ```json
    {
    "status": "error",
    "code": 405,
    "message": "GET method is disabled"
    }
    ```

## 5. Obtaining Credentials from DNS Providers

### 5.1. Generate Cloudflare API Token

> ⚠️ **Important**: This service only supports API Token, not Global API Key.

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/), go to My Profile → API Tokens

    Or directly visit [Cloudflare Dashboard API Tokens](https://dash.cloudflare.com/profile/api-tokens)

2. Click Create Token

   1. In Permissions, add the following permissions:

        - Zone - DNS - Edit
        - Zone - Zone - Read

   2. Configure Zone Resources as needed

        You can restrict to the domains you need to manage, or set to all zones (All zones / All zones from an account).

   3. Configure Client IP Address Filtering as needed

        > Note: If you restrict IPs, make sure the server's IP is included.

3. Create and save the generated API Token

    Note: The API Token is only shown once, please keep it safe.

### 5.2. Generate Aliyun AccessKey

Go to [Aliyun RAM Access Control](https://ram.console.aliyun.com/users), create a RAM user, note:

1. Enable AccessKey access, keep console access disabled

    After creation, save `AccessKey ID` and `AccessKey Secret`.

    Note: `AccessKey Secret` is only shown once, please keep it safe.

2. Grant permissions to the user

    Grant the user the `AliyunDNSFullAccess` policy (recommended), or at least a [custom policy](https://ram.console.aliyun.com/policies) with the following permissions:

    - `alidns:AddDomainRecord`
    - `alidns:DescribeDomainRecords`
    - `alidns:UpdateDomainRecord`
    - `alidns:UpdateDomainRecordRemark`
    - `alidns:DeleteDomainRecord` permission is **not required**

        There is currently no function to delete DNS records. If needed, please delete manually in the console.

    If using script editing:

    ```json
    {
      "Version": "1",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "alidns:AddDomainRecord",
            "alidns:UpdateDomainRecord",
            "alidns:DescribeDomainRecords",
            "alidns:UpdateDomainRecordRemark"
          ],
          "Resource": "*"
        }
      ]
    }
    ```

    If you want to restrict permissions to specific domains, set restrictions in the "Resource" section.

3. Network access control policy

    > Note: If you restrict IPs, make sure the server's IP is included.

    There are two options:

    1. Add network access restriction policy to the generated AccessKey

        The restriction applies only to this AccessKey.

    2. Add account-level AccessKey network access policy to the Aliyun account

        The restriction applies to all AccessKeys under the account.

        Set at [RAM Access Control > Settings > Network Access Restriction](https://ram.console.aliyun.com/settings) by configuring the "Allowed source network addresses for AccessKey access".

        > Note: If an AccessKey has its own restriction, it overrides the account-level policy.

4. Save the generated AccessKey

    Note: AccessKey Secret is only shown once, please keep it safe.

### 5.3. Generate Tencent Cloud API Key

> ⚠️ **Important**: This service only supports Tencent DNSPod Mainland China edition, not the International edition (`api.dnspod.com`). The international edition still uses the old API, which is incompatible with the Tencent Cloud SDK.

1. Go to [Tencent Cloud Sub-user Management](https://console.cloud.tencent.com/cam), add a new sub-user. Select "Custom Creation".

2. User settings

    1. User type must be "Can access resources and receive messages"
    2. Enable "Programmatic Access", keep "Tencent Cloud Console Access" disabled

3. Grant permissions to the user

    Grant the user the `QcloudDNSPodFullAccess` policy (recommended), or at least a [custom policy](https://console.cloud.tencent.com/cam/policy) with the following permissions:

    1. Effect: Allow
    2. Service: Cloud DNS (DNSPod)
    3. Action:
        - `dnspod:DescribeRecordList`
        - `dnspod:CreateRecord`
        - `dnspod:ModifyRecord`
        - `dnspod:DeleteRecord` permission is **not required**

            There is currently no function to delete DNS records. If needed, please delete manually in the console.

    4. Resource: all resources

        If you need to restrict permissions to specific domains, set it here.

    5. Condition

        If you need to restrict access to specific IPs, set it here.

        > Note: If you restrict IPs, make sure the server's IP is included.
        >
        > In addition, for the above interfaces, Tencent Cloud currently does not seem to enforce source IP restrictions.

    If using JSON configuration:

    ```json
    {
      "version": "2.0",
      "statement": [
        {
          "effect": "allow",
          "action": [
            "dnspod:DescribeRecordList",
            "dnspod:CreateRecord",
            "dnspod:ModifyRecord"
          ],
          "resource": [
            "*"
          ]
        }
      ]
    }
    ```

4. Save the generated SecretId and SecretKey

    Note: SecretKey is only shown once, please keep it safe.

## 6. RouterOS Script Examples

Due to limited JSON support in RouterOS, you can determine update success as follows:

- HTTP status code is 200 on success
- Response body contains the string `"status":"success"`

For example:

```routeros
:if ([:find ($result->"data") "\"status\":\"success\""] != nil) do={
    :log info "Success"
}
```

### 6.1. Basic Script

```routeros
# DDNS update script - run every minute
# Scheduler: /system scheduler add name=ddns interval=1m on-event=ddns-update

:local ddnsServer "http://your-server:38080"
:local authToken "your-auth-token"
:local cfToken "your-cloudflare-token"
:local zone "example.com"
:local record "home"
:local ttl "600"
:local comment "Updated by RouterOS DDNS script"
:local interface "pppoe-out1"

# Get current IP
:local currentIP [/ip address get [find interface=$interface] address]
:set currentIP [:pick $currentIP 0 [:find $currentIP "/"]]

# Build request URL and Headers
:local url "$ddnsServer/update?provider=cloudflare&zone=$zone&record=$record&type=A&value=$currentIP&ttl=$ttl&comment=$comment"
:local authHeader "Authorization: Bearer $authToken"
:local credHeader "X-Upstream-Authorization: ApiKey secret=\"$cfToken\""

:local result [/tool fetch url=$url http-header-field="$authHeader,$credHeader" as-value output=user]

# Check result
:if ([:find ($result->"data") "\"status\":\"success\""] != nil) do={
    :log info "DDNS: Update successful for $record.$zone -> $currentIP"
} else={
    :log warning "DDNS: Update failed - $($result->'data')"
}
```

### 6.2. Script Supporting IPv6

```routeros
# IPv6 DDNS update
:local ddnsServer "http://your-server:38080"
:local authToken "your-auth-token"
:local cfToken "your-cloudflare-token"
:local zone "example.com"
:local record "home"
:local ttl "600"
:local comment "Updated by RouterOS DDNS script"

# Get public IPv6 address (filter link-local)
:local ipv6Addr ""
:foreach addr in=[/ipv6 address find where global] do={
    :set ipv6Addr [/ipv6 address get $addr address]
    :set ipv6Addr [:pick $ipv6Addr 0 [:find $ipv6Addr "/"]]
}

:if ($ipv6Addr != "") do={
    :local url "$ddnsServer/update?provider=cloudflare&zone=$zone&record=$record&type=AAAA&value=$ipv6Addr&ttl=$ttl&comment=$comment"
    :local authHeader "Authorization: Bearer $authToken"
    :local credHeader "X-Upstream-Authorization: ApiKey secret=\"$cfToken\""
    /tool fetch url=$url http-header-field="$authHeader,$credHeader" as-value output=user
}
```

## 7. Troubleshooting

### 7.1. Common Errors

| Error Message                  | Cause                                                                     | Solution                                                                                                                 |
|--------------------------------|---------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| `Missing authentication token` | Server authentication enabled, but no token provided                      | Check if the server token is provided correctly                                                                          |
| `Invalid authentication token` | Server authentication enabled, but authentication failed                  | Check if the server token is correct                                                                                     |
| `Missing required credential`  | Missing provider credential                                               | Ensure DNS provider credentials are provided                                                                             |
| `Zone not found for domain`    | Domain does not exist at DNS provider, <br>or Cloudflare credential error | Check if the domain is correct, <br>added to the provider, <br>or if credentials are correct and have proper permissions |
| `Failed to query DNS records`  | Aliyun / Tencent credential error                                         | Ensure correct Aliyun / Tencent credentials are provided and have proper permissions                                     |
| `Multiple records found`       | Duplicate records exist                                                   | Manually clean up duplicate records in the DNS console                                                                   |

### 7.2. Debug Mode

Enable DEBUG level logging to view detailed information:

```bash
$ uv run ddns-gateway --log-level DEBUG
```

Or set in the configuration file:

```toml
[logging]
level = "DEBUG"
```

## 8. Risk Notice

Most of the source code in this project is AI-assisted generated, including but not limited to function implementation, code structure, and some documentation content.

Please evaluate the code yourself before use and use at your own risk.
