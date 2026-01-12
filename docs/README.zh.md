# DDNS Gateway

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Languages**: [English](docs/README.en.md) | [简体中文](docs/README.zh.md)

DDNS Gateway 是一个为 RouterOS 设计的 DDNS 更新服务，整体采用异步架构实现。

本服务作为中间层，接收 RouterOS 发起的 HTTP 更新请求，并调用各 DNS 服务商的 API 完成解析记录的查询与更新。

⚠️ 注意：访问远端服务器时，**请务必使用 HTTPS 协议发起请求**，防止造成密钥泄露！

## 1. 支持的服务商

| 服务商        | 认证方式                        | 解析记录备注 | 备注说明                                          |
|:--------------|:--------------------------------|:-------------|:--------------------------------------------------|
| Cloudflare    | API Token                       | 支持         | **不支持** Global API Key                         |
| 阿里云 DNS    | AccessKey ID + AccessKey Secret | 支持         |                                                   |
| 腾讯云 DNSPod | SecretId + SecretKey            | 支持         | **仅支持国内版**，不支持国际版 (`api.dnspod.com`) |

注意，对于阿里云而言，其解析记录备注需要在添加 / 更新域名记录后，单独调用 API 进行设置。**若记录更新成功而更新备注失败，则依旧会返回 `"status": "success"` (`200`)**，但会在 `warnings` 中给出说明。详见后述。

## 2. 安装

### 2.1. 使用 UV 安装（推荐）

```shell
# 克隆仓库
$ git clone https://github.com/yourusername/DDNS-Gateway.git
$ cd DDNS-Gateway

# 创建虚拟环境, 安装依赖
$ uv sync

# 运行 (二选一)
$ uv run ddns-gateway
$ ./.venv/bin/ddns-gateway

INFO:     Started server process [37951]
INFO:     Waiting for application startup.
2026-01-12 03:58:51 INFO  [ddns_gateway.server] DDNS Gateway starting on "0.0.0.0:38080" (Methods: GET, POST).
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:38080 (Press CTRL+C to quit)
```

### 2.2. 使用 pip 安装

> 注意：请确保 Python 不低于 3.12。

```shell
pip install -e .

ddns-gateway
```

## 3. 配置

配置优先级：

1. 命令行参数（最高）

2. 配置文件

3. 默认值（最低）

### 3.1. 命令行参数

```shell
# 基本用法
uv run ddns-gateway --help
uv run ddns-gateway --config /path/to/config.toml
uv run ddns-gateway --host 127.0.0.1 --port 9000
uv run ddns-gateway --log-level DEBUG

# 是否将日志输出到文件 (注意: 需自行处理好日志轮转)
uv run ddns-gateway --log-file-enabled --log-file-path "~/log/ddns-gateway.log"
uv run ddns-gateway --log-file-disabled

# 禁用认证
uv run ddns-gateway --auth-disabled

# 启用认证并指定 Token
uv run ddns-gateway --auth-enabled --auth-tokens tk1 tk2                # 空格分隔
uv run ddns-gateway --auth-enabled --auth-tokens tk1 --auth-tokens tk1  # 多次指定

# 指定 HTTP 方法 (逗号分隔)
uv run ddns-gateway --methods "get,post"  # 启用 GET 和 POST 方法
uv run ddns-gateway --methods post        # 仅启用 POST 方法
```

详细参数说明：

| 参数                                          | 作用                           | 说明                                                |
|:----------------------------------------------|:-------------------------------|:----------------------------------------------------|
| `--config`                                    | 指定配置文件路径               |                                                     |
| `--host`                                      | 监听地址                       |                                                     |
| `--port`                                      | 监听端口                       |                                                     |
| `--log-level`                                 | 日志级别                       |                                                     |
| `--auth-enabled`<br>`--auth-disabled`         | 启用 / 禁用服务端身份验证      | 两者互斥，不可同时指定                              |
| `--auth-tokens`                               | 身份验证 Token 列表            | 多个 Token 可用空格分隔，或也可多次指定（见上述）   |
| `--methods`                                   | `/update` 端点启用的 HTTP 方法 | 使用逗号分隔（见上述），且 GET 与 POST 至少启用一个 |
| `--log-file-enabled`<br>`--log-file-disabled` | 启用 / 禁用输出日志到文件      | 两者互斥，不可同时指定                              |
| `--log-file-path`                             | 日志文件路径                   | 须确保具有适当权限，并自行处理好日志轮转            |
| `--health-enabled`<br>`--health-disabled`     | 启用 / 禁用 `/health` 端点     | 两者互斥，不可同时指定                              |

### 3.2. 配置文件

配置文件使用 TOML 格式，默认路径是本目录下的 `config.toml` 文件。

可通过 `--config` 参数指定配置文件路径，例如 `--config /path/to/config.toml`。

配置文件格式及 **默认值**：

```toml
[server]
host = "0.0.0.0"     # 监听地址. 如使用 Nginx 反代, 将此处设置为 "127.0.0.1" 即可
port = 38080         # 监听端口

[auth]
enabled = false      # 是否启用身份验证. 若启用, 则请求时必须附带有效的 Token. 未附带 Token 或 Token 无效时, 将返回 401 / 403 错误
tokens = []          # 若启用身份验证, 必须在此处配置有效的 Token 列表. 若且启用了验证而此列表为空, 则所有请求都会被拒绝

[methods]
get_enabled = true   # 是否启用 GET /update 端点. 若禁用, 请求将返回 405 Method Not Allowed. 注意: get_enabled 与 post_enabled 至少需启用一个
post_enabled = true  # 是否启用 POST /update 端点. 若禁用, 请求将返回 405 Method Not Allowed. 注意: get_enabled 与 post_enabled 至少需启用一个

[logging]
level = "INFO"                           # 日志级别. 可选值: DEBUG, INFO, WARNING, ERROR, CRITICAL
file_enabled = false                     # 是否将日志记录到文件
file_path = "/var/log/ddns-gateway.log"  # 日志文件路径. 注意: 请确保用户对此文件有适当权限, 并请自行处理好日志轮转

[health]
enabled = false                          # 是否启用 "/health" 端点
```

配置文件会进行类型校验。若配置值类型不正确且无法自动转换，程序会在启动时报错并退出。

> 注：部分类型支持自动转换（如 `"8080"` → `8080`，`"true"` / `"yes"` → `true`），但无法转换的值仍会报错。

各配置项的期望类型如下：

| 配置项                 | 期望类型    |
|:-----------------------|:------------|
| `server.host`          | `str`       |
| `server.port`          | `int`       |
| `auth.enabled`         | `bool`      |
| `auth.tokens`          | `list[str]` |
| `methods.get_enabled`  | `bool`      |
| `methods.post_enabled` | `bool`      |
| `logging.level`        | `str`       |
| `logging.file_enabled` | `bool`      |
| `logging.file_path`    | `str`       |
| `health.enabled`       | `bool`      |

## 4. API 参考

### 4.1. `/update`

支持 `GET` / `POST` 方法（除非在配置文件中禁用某个方法），用于更新 DNS 记录。

#### 4.1.1. 请求参数 (Query / Body)

1. **GET 请求**：参数通过 Query String 传递

2. **POST 请求**：参数通过 JSON Body 传递 (Content-Type: `application/json`)

| 参数       | 必填 | 说明                                                                |
|------------|------|---------------------------------------------------------------------|
| `provider` | 是   | DNS 服务商。可选值：`Cloudflare`, `aliyun`, `tencent`               |
| `zone`     | 是   | DNS 区域（主域名），如 `example.com`                                |
| `record`   | 是   | 主机记录名，如 `home`、`@`、`www`                                   |
| `type`     | 是   | 记录类型，可选值：`A`, `AAAA`, `CNAME`, `TXT`                       |
| `value`    | 是   | 记录值（IP 地址、目标域名或文本内容）                               |
| `ttl`      | 否   | TTL（秒）。若不提供，创建记录时使用服务商默认值，更新记录时保持原值 |
| `comment`  | 否   | DNS 记录备注                                                        |

腾讯云 / 阿里云目前默认 TTL 为 600 秒；Cloudflare 默认为 Auto，目前其值为 300 秒。

注意：TTL 不要小于账号允许的最小 TTL，否则会失败。目前 Cloudflare 非 Enterprise 账号，TTL 最小为 60 秒，最大为 1 天。

> 参见 [Cloudflare: Time to Live (TTL)](https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/)。

#### 4.1.2. HTTP Header

| Header                     | 作用                        | 必填   | 说明                                                  |
|:---------------------------|-----------------------------|:-------|:------------------------------------------------------|
| `Authorization`            | 用于访问本 API 服务本身     | 视情况 | `Bearer <token>` 格式，<br>当服务端启用认证时需要提供 |
| `X-Upstream-Authorization` | 用于调用上游 DNS 服务商 API | 是     | 使用 ApiKey 方案（见下述）                            |

#### 4.1.3. X-Upstream-Authorization 凭证格式

`X-Upstream-Authorization` 使用 ApiKey 认证方案，基本格式如下：

> 需要注意引号。

```text
ApiKey id="<ID>", secret="<SECRET>"
```

若某些服务商不需要 `id`（例如 Cloudflare），可省略：

> 需要注意引号。

```text
ApiKey secret="<SECRET>"
```

各 DNS 服务商凭证要求：

1. Cloudflare：仅需提供 `secret`，若提供 `id` 将被自动忽略

    - `secret`：Cloudflare API Token

    示例：

    ```text
    ApiKey secret="tusrhvdjhn39kawczvsdqd9xtqwzdc"
    ```

2. 阿里云：需同时提供 `id` 和 `secret`

    - `id`：阿里云 AccessKey ID

    - `secret`：阿里云 AccessKey Secret

    示例：

    ```text
    ApiKey id="xfu6g27qekpmzf6yrbfr5t368eknyy", secret="zgrf68zzpgujurhr2kmyxv5cmry56m"
    ```

3. 腾讯云：需同时提供 `id` 和 `secret`

    - `id`：腾讯云 SecretId

    - `secret`：腾讯云 SecretKey

    示例：

    ```text
    ApiKey id="es8q56j23k3393f4qgpeype2284jb6", secret="svdzwz6jmx9vgwq6zr7rurnumetdz2"
    ```

### 4.2. `/health`

> **注意**：此端点默认 **禁用**，须通过配置文件或命令行参数启用。且此端点 **不受身份验证配置影响（始终无需鉴权）**。

支持 `GET` 方法，用于负载均衡健康检查或服务监控。

响应示例：`{"status": "ok"}` / `{"detail":"Not Found"}`（禁用时）。

### 4.3. 请求示例

> ⚠️ 注意：若是访问远端服务器（而非本机服务器），**请务必使用 HTTPS 协议发起请求**，防止造成密钥泄露！

```shell
# Cloudflare (GET)

curl "http://localhost:38080/update?provider=Cloudflare&zone=example.com&record=home&type=A&value=1.2.3.4&ttl=600&comment=Hello%20World" \
  -H "Authorization: Bearer YOUR_SERVER_TOKEN" \
  -H 'X-Upstream-Authorization: ApiKey secret="YOUR_CF_TOKEN"'

# Cloudflare (POST, application/json)

curl -X POST "http://localhost:38080/update" \
  -H "Authorization: Bearer YOUR_SERVER_TOKEN" \
  -H 'X-Upstream-Authorization: ApiKey secret="YOUR_CF_TOKEN"' \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "Cloudflare",
    "zone": "example.com",
    "record": "home",
    "type": "A",
    "value": "1.2.3.4",
    "ttl": 600,
    "comment": "Hello World"
  }'

# 阿里云 (GET)

curl "http://localhost:38080/update?provider=aliyun&zone=example.com&record=home&type=A&value=1.2.3.4&ttl=600&comment=Hello%20World" \
  -H "Authorization: Bearer YOUR_SERVER_TOKEN" \
  -H 'X-Upstream-Authorization: ApiKey id="YOUR_ACCESS_KEY_ID", secret="YOUR_ACCESS_KEY_SECRET"'

# 腾讯云 (GET)

curl "http://localhost:38080/update?provider=tencent&zone=example.com&record=home&type=A&value=1.2.3.4&ttl=600&comment=Hello%20World" \
  -H "Authorization: Bearer YOUR_SERVER_TOKEN" \
  -H 'X-Upstream-Authorization: ApiKey id="YOUR_SECRET_ID", secret="YOUR_SECRET_KEY"'

# 健康检查

curl "http://localhost:38080/health"
```

### 4.4. 响应示例

注意：

1. 若某字段为空，则不会返回

    例如，当某记录发生变化并成功更新后，JSON 中会包含 `data.previous_value`。但如果是新增记录、或是记录未发生变化，则不会包含此项。

2. 关于 `provider_metadata`

    对于 Cloudflare，其包含 `record_id`、`zone_id` 以及 `extra`（包含 `cf_ray` 等）。但若记录未发生变化，则不会包含 `cf_ray`。

    对于阿里云 / 腾讯云，其包含 `record_id`、`request_id`。但若记录未发生变化，则不会包含 `request_id`。

3. 对于阿里云而言，其解析记录备注需要在添加 / 更新域名记录后，单独调用 API 进行设置

    若记录更新成功而更新备注失败，**则依旧会返回 `"status": "success"` (`200`)**，但会在 `warnings` 中给出说明。

```json
// Cloudflare

{
  "status": "success",
  "code": 200,
  "message": "DNS record created for test.example.com",
  "action": "created",
  "data": {
    "provider": "cloudflare",
    "zone": "example.com",
    "record": "test",
    "fqdn": "test.example.com",
    "type": "A",
    "value": "1.2.3.4",
    "ttl": 600
  },
  "provider_metadata": {
    "record_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "zone_id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "extra": {
      "cf_ray": "xxxxxxxxxxxxxxxx-xxx"
    }
  },
  "warnings": []
}

// 阿里云

{
  "status": "success",
  "code": 200,
  "message": "DNS record created for test.example.com",
  "action": "created",
  "data": {
    "provider": "aliyun",
    "zone": "example.com",
    "record": "test",
    "fqdn": "test.example.com",
    "type": "A",
    "value": "1.2.3.4",
    "ttl": 600
  },
  "provider_metadata": {
    "record_id": "xxxxxxxxxxxxxxxxxxx",
    "request_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  },
  "warnings": []
}

// 腾讯云

{
  "status": "success",
  "code": 200,
  "message": "DNS record created for test.example.com",
  "action": "created",
  "data": {
    "provider": "tencent",
    "zone": "example.com",
    "record": "test",
    "fqdn": "test.example.com",
    "type": "A",
    "value": "1.2.3.4",
    "ttl": 600
  },
  "provider_metadata": {
    "record_id": "xxxxxxxxxx",
    "request_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  },
  "warnings": []
}

// 阿里云: 记录更新成功, 但备注更新失败

{
  "status": "success",
  "code": 200,
  "message": "DNS record updated for test.example.com",
  "action": "updated",
  "data": {
    "provider": "aliyun",
    "zone": "example.com",
    "record": "test",
    "fqdn": "test.example.com",
    "type": "A",
    "value": "1.2.3.4",
    "ttl": 600
  },
  "provider_metadata": {
    "record_id": "xxxxxxxxxxxxxxxxxxx"
  },
  "warnings": [
    {
      "code": "comment_partial",
      "message": "Record updated but failed to update remark"
    }
  ]
}
```

当发生服务端 Server Token 认证失败 (401 / 403) 或请求方法被禁用 (405) 时，API 将返回 JSON 格式的错误信息。例如：

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

## 5. 从 DNS 服务商处获取凭证

### 5.1. 生成 Cloudflare API Token

> ⚠️ 本服务仅支持 API Token，不支持 Global API Key。

1. 登录 [Cloudflare Dashboard](https://dash.Cloudflare.com/)，进入 My Profile → API Tokens

    也可以直接访问 [Cloudflare Dashboard API Tokens](https://dash.Cloudflare.com/profile/api-tokens)

2. 点击 Create Token

   1. Permissions 中添加以下权限：

        - Zone - DNS - Edit

        - Zone - Zone - Read

   2. Zone Resources 根据需要配置

        可以限制为需要管理的域名，也可以设置为全部域名 (All zones / All zones from an account)。

   3. Client IP Address Filtering 根据需要配置

        > 注意：如果限制 IP，需要确保此服务端的 IP 在其中。

3. 创建并保存生成的 API Token

    注意：API Token 只显示一次，请妥善保存。

### 5.2. 生成阿里云 AccessKey

打开 [阿里云 RAM 访问控制](https://ram.console.aliyun.com/users)，创建一个 RAM 用户，注意：

1. 访问方式需要启用「使用永久 AccessKey 访问」，控制台访问保持禁用即可

    创建成功好保存好 `AccessKey ID` 和 `AccessKey Secret`。

    注意：`AccessKey Secret` 只显示一次，请妥善保存。

2. 对用户授权

    需要对此用户授权 `AliyunDNSFullAccess` 权限策略（推荐），或至少包含以下自定义权限的 [自定义权限策略](https://ram.console.aliyun.com/policies)：

    - `alidns:AddDomainRecord`

    - `alidns:DescribeDomainRecords`（注意不是 `alidns:DescribeSubDomainRecords`）

    - `alidns:UpdateDomainRecord`

    - `alidns:UpdateDomainRecordRemark`

    - 不需要 `alidns:DeleteDomainRecord` 权限

        暂时没有删除解析记录的功能。如有需要，请至控制台手工删除。

    如果使用脚本编辑方式：

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

    如果需要限制仅对指定域名具有权限，那么在「资源」部分限制即可。

3. 网络访问控制策略

    > 注意：如果限制 IP，需要确保此服务端的 IP 在其中。

    有两个选项：

    1. 为生成的 AccessKey 添加 AccessKey 级网络访问限制策略

        设置的网络访问限制策略只对此 AccessKey 生效。

    2. 为阿里云账号添加账号级 AccessKey 网络访问控制策略

        设置的网络访问限制策略对阿里云账号下的所有 AccessKey 生效。

        设置地址位于 [RAM 访问控制 > 设置 > 网络访问限制](https://ram.console.aliyun.com/settings)）设置「允许通过 AccessKey 访问的来源网络地址」。

        > 注意：如果某个 AccessKey 单独设置了网络访问限制策略，那么会覆盖这里的设置。

4. 保存生成的 AccessKey

    注意：AccessKey Secret 只显示一次，请妥善保存。

### 5.3. 生成腾讯云 API 密钥

> ⚠️ **重要**：本服务仅支持腾讯云 DNSPod 国内版，不支持 DNSPod 国际版 (`api.dnspod.com`)。国际版目前仍使用旧版 API，与腾讯云 SDK 不兼容。

1. 打开 [腾讯云子用户管理](https://console.cloud.tencent.com/cam)，添加一个新的子用户。添加时，选择「自定义创建」。

2. 用户设置

    1. 用户类型需要选择「可访问资源并接收消息」

    2. 访问方式需要开启「编程访问」，「腾讯云控制台访问」保持禁用即可

3. 对用户授权

    需要对此用户授权 `QcloudDNSPodFullAccess` 权限策略（推荐），或至少包含以下自定义权限的 [自定义权限策略](https://console.cloud.tencent.com/cam/policy)：

    1. 效果 (Effect)：允许

    2. 服务 (Service)：云解析 DNS (DNSPod)

    3. 操作 (Action)

        - `dnspod:DescribeRecordList`

        - `dnspod:CreateRecord`

        - `dnspod:ModifyRecord`

        - 不需要 `dnspod:DeleteRecord` 权限

            暂时没有删除解析记录的功能。如有需要，请至控制台手工删除。

    4. 资源 (Resource)：所有资源

        但如果需要限制仅对指定域名具有权限，那么需要在此处设置。

    5. 条件 (Condition)

        如需限制仅指定 IP 具有访问权限，那么在此处限制。

        > 注意：如果限制 IP，需要确保此服务端的 IP 在其中。
        >
        > 另外，对于上述接口，腾讯云目前似乎尚未来源 IP 限制。

    如果使用 JSON 配置：

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

4. 保存生成的 SecretId 和 SecretKey

    注意：SecretKey 只显示一次，请妥善保存。

## 6. RouterOS 脚本示例

由于 RouterOS 在解析 JSON 方面的支持有限，可采用以下方式判断是否更新成功：

- 成功时 HTTP 状态码为 200

- 响应体包含 `"status": "success"` 字符串

例如：

```routeros
:if ([:find ($result->"data") "\"status\": \"success\""] != nil) do={
    :log info "DDNS: Update successful"
} else={
    :log warning "DDNS: Update failed"
}
```

⚠️ 再次提示：访问远端服务器时，**请务必使用 HTTPS 协议发起请求**，防止造成密钥泄露！

### 6.1. 基本脚本

```routeros
# DDNS 更新脚本 - 每分钟运行一次
# Scheduler: /system scheduler add name=ddns interval=1m on-event=ddns-update

:local ddnsServer "https://your-server:38080"
:local authToken "your-auth-token"
:local cfToken "your-Cloudflare-token"
:local zone "example.com"
:local record "home"
:local ttl "600"
:local comment "Updated by RouterOS DDNS script"
:local interface "pppoe-out1"

# 获取当前 IP
:local currentIP [/ip address get [find interface=$interface] address]
:set currentIP [:pick $currentIP 0 [:find $currentIP "/"]]

# 构建请求 URL 和 Headers
:local url "$ddnsServer/update?provider=Cloudflare&zone=$zone&record=$record&type=A&value=$currentIP&ttl=$ttl&comment=$comment"
:local authHeader "Authorization: Bearer $authToken"
:local credHeader "X-Upstream-Authorization: ApiKey secret=\"$cfToken\""

:local result [/tool fetch url=$url http-header-field="$authHeader,$credHeader" as-value output=user]

# 检查结果
:if ([:find ($result->"data") "\"status\": \"success\""] != nil) do={
    :log info "DDNS: Update successful for $record.$zone -> $currentIP"
} else={
    :log warning "DDNS: Update failed - $($result->'data')"
}
```

### 6.2. 支持 IPv6 的脚本

```routeros
# IPv6 DDNS 更新
:local ddnsServer "https://your-server:38080"
:local authToken "your-auth-token"
:local cfToken "your-Cloudflare-token"
:local zone "example.com"
:local record "home"
:local ttl "600"
:local comment "Updated by RouterOS DDNS script"

# 获取公网 IPv6 地址（过滤 link-local）
:local ipv6Addr ""
:foreach addr in=[/ipv6 address find where global] do={
    :set ipv6Addr [/ipv6 address get $addr address]
    :set ipv6Addr [:pick $ipv6Addr 0 [:find $ipv6Addr "/"]]
}

:if ($ipv6Addr != "") do={
    :local url "$ddnsServer/update?provider=Cloudflare&zone=$zone&record=$record&type=AAAA&value=$ipv6Addr&ttl=$ttl&comment=$comment"
    :local authHeader "Authorization: Bearer $authToken"
    :local credHeader "X-Upstream-Authorization: ApiKey secret=\"$cfToken\""
    /tool fetch url=$url http-header-field="$authHeader,$credHeader" as-value output=user
}
```

## 7. 故障排除

### 7.1. 常见错误

| 错误信息                       | 原因                                                  | 解决方法                                                                                                                                  |
|--------------------------------|-------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| `Missing authentication token` | 服务器启用了身份验证，但未提供 Token                  | 检查是否正确提供了 Server Token                                                                                                           |
| `Invalid authentication token` | 服务器启用了身份验证，但认证失败                      | 检查 Server Token 是否正确                                                                                                                |
| `Missing required credentials` | 缺少服务商凭证                                        | 确认是否正确提供了 DNS 服务商凭证参数                                                                                                     |
| `Zone not found for domain`    | 域名不存在于 DNS 服务商中，<br>或 Cloudflare 凭证错误 | 确认域名是否正确，<br>或确认域名已正确添加至 DNS 服务商处，<br>或确认 Cloudflare 凭证是否正确，<br>或确认 Cloudflare Token 是否有正确权限 |
| `Failed to query DNS records`  | 阿里云 / 腾讯云凭证错误                               | 确认提供了正确的阿里云 / 腾讯云凭证，<br>并确认其是否具有正确权限                                                                         |
| `Multiple records found`       | 存在重复记录                                          | 手动清理 DNS 控制台中的重复记录                                                                                                           |

若密钥错误 / 权限不够，可至相应云服务商控制台处，检查相应 Key 的访问日志查看具体原因。

### 7.2. 调试模式

启用 DEBUG 级别日志查看详细信息：

```shell
$ uv run ddns-gateway --log-level DEBUG
```

或在配置文件中设置：

```toml
[logging]
level = "DEBUG"
```

## 8. 风险提示

1. 本项目自身 **不提供** 高级安全功能，例如：

   1. 访问速率限制 (Rate Limiting)

       程序内部未限制请求频率，无法防止暴力破解或 DOS 攻击。

   2. IP 访问控制

       无内置的黑白名单 (IP Allow / Blocklist) 机制。

   3. Web 应用防火墙 (WAF)

       无内置针对 SQL 注入、XSS 等常见 Web 攻击的防护。

    因此，**强烈建议不要将本服务直接暴露在公网**（直接监听 `0.0.0.0` 且无前置防护），并考虑采用以下措施进行加固：

    1. 使用 Nginx 反向代理

        建议使用 Nginx 等作为反向代理，并在 Nginx 层实现安全限制。

        注意：**需要将服务端的监听地址改为 `127.0.0.1`**，防止外部直接访问。

    2. 使用 Cloudflare (套 CF)

        强烈建议使用。

    3. 其他

       - 启用 HTTPS

            **请务必在反向代理层配置 SSL/TLS 证书**，并**使用 HTTPS 进行访问**，以防止 Server Token / Provider Token 在传输中泄露。

       - 启用服务端身份认证并使用强 Server Token（默认禁用）

            `config.toml` 中的 `server_token` 等效于密码，请务必设置得足够长且随机。

       - Fail2Ban

            如果开启了文件日志，可以使用 Fail2Ban 监控日志文件，一旦发现大量 401 (Unauthorized) 或 403 (Forbidden) 错误，自动在防火墙层面封锁对应 IP。

2. **本项目大部分源代码由 AI 生成**，包括但不限于功能实现、代码结构以及部分文档内容。

    请在使用前自行对代码进行评估，风险自负。
