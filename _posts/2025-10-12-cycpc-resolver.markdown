---
layout: post
title: CYCPC 滚榜记录
date: 2025-10-12 00:46:43 +0800
category: 技术向
tags: [xcpc, resolver]
image: https://s1.bpoj.top/6001fdfc992331d6793fb7edf532b0bf.png
locale: zh_CN
description: CYCPC Resovler Notes
math: false
---

icpc tools resolver 版本：2.6.1324

hydro 导出 cdp 后，拿到 event-feed.ndjson，运行：

```
awards.bat event-feed.ndjson --medals 4 4 4 --rank 5 --fts true true
```

（金银铜分别 4 名，前 5 名有 rank 奖）

得到 event-feed-awards.ndjson 文件，运行以下命令开始滚榜：

```
resolver.bat event-feed-awards.ndjson --display_name "{team.display_name}（{org.formal_name}）"
```

如果使用 cdp 包，队伍头像放在 .cdp/organizations/org-xxx/logo.png，队伍获奖展示照片放在 .cdp/teams/team-xxx/photo.png（为空则默认展示比赛 logo），比赛 logo 放在 .cdp/contest/logo.png。

---

1. 使用 cdp 包滚榜并设置滚榜速度为 2 倍（小于 1 为减速）

```
resolver.bat ./cdp/ --display_name "{team.display_name}（{org.formal_name}）" --speed 2
```

2. 中文字体无法显示

在 resolver.bat 里写 `set ICPC_FONT="DengXian"`，或者修改对应环境变量。

3. cdp包格式

```
./cdp
│  event-feed.ndjson
│
├─contest
│      logo.png
│
├─organizations
│  ├─org-85
│  │      logo.png
|
└─teams
    └─team-85
            photo.png
```

4. 常用快捷键

空格开始滚榜，上下箭头控制滚榜速度，ctrl+q 退出。