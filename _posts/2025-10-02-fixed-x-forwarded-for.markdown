---
layout: post
title: 记一次 X-Forwarded-For 问题排查
date: 2025-11-04 19:05:05 +0800
category: 技术向
tags: [caddy, aliyun]
# image: 
locale: zh_CN
description: X-Forwarded-For 问题排查
math: false
---

环境：阿里云边缘安全加速 ESA、Caddy

Caddyfile:

```
bpoj.top {
  encode zstd gzip
  log {
    output file /data/access.log {
      roll_size 1gb
      roll_keep_for 72h
    }
    format json
  }
  # Handle static files directly, for better performance.
  root * /root/.hydro/static
  @static {
    file {
      try_files {path}
    }
  }
  handle @static {
    file_server
  }
  handle {
    reverse_proxy http://127.0.0.1:8888
  }
}
```

使用 Caddy 作为反代服务器时，会出现后端 `X-Forwarded-For` 取值异常的情况，导致无法获取用户的真实 ip。

原因分析：如果 Caddyfile 没有配置 `trusted_proxies`，Caddy 会忽略客户端传来的 xff 值并自己解析 xff 给上游，这样后端实际拿到的 `X-Forwarded-For` 值一般是 `client_ip`，也就是阿里云加速节点的实际 ip。

相关文档：

- https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#defaults
- https://caddyserver.com/docs/caddyfile/options#trusted-proxies

解决方案：

```
{
  servers {
    trusted_proxies static <回源 ip 段>
    trusted_proxies_strict
    client_ip_headers X-Forwarded-For ali-real-client-ip
  }
}
bpoj.top {
  encode zstd gzip
  log {
    output file /data/access.log {
      roll_size 1gb
      roll_keep_for 72h
    }
    format json
  }
  # Handle static files directly, for better performance.
  root * /root/.hydro/static
  @static {
    file {
      try_files {path}
    }
  }
  handle @static {
    file_server
  }
  handle {
    reverse_proxy http://127.0.0.1:8888
  }
}
```

或者 esa 使用默认请求头配置，后端直接读取 `ali-real-client-ip` 标头。