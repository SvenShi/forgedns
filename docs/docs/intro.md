---
id: intro
title: ForgeDNS
sidebar_position: 1
slug: /
---

本文档重点说明 ForgeDNS 的配置结构、插件体系、管理 API、常见策略组合，以及架构与性能说明。

建议按照以下顺序阅读本文档：

1. 阅读《[快速开始](quickstart.md)》，先根据你的环境选择合适的安装方式并完成首次启动。
2. 阅读《[配置总览](configuration.md)》，了解顶层 YAML 结构与 `sequence` 编排方式。
3. 阅读《[插件总览](plugin-reference/overview.md)》下的四类插件文档，建立 `server / executor / matcher / provider` 的结构认知。
4. 在接入运维平台、控制平面或观测系统时，阅读《[管理 API](api.md)》。
5. 在进行策略落地与组合设计时，阅读《[常见策略场景](scenarios.md)》。
6. 在理解内部设计与性能方向时，阅读《[架构与设计](architecture-and-design.md)》与《[性能与基准](benchmarks.md)》。

## 文档范围

当前内置插件如下：

<div className="doc-plugin-grid">
  <div className="doc-plugin-grid__column">
    <section className="doc-plugin-card">
      <div className="doc-plugin-card__header">
        <div className="doc-plugin-card__eyebrow">入口层</div>
        <h3 className="doc-plugin-card__title">
          <a href="plugin-reference/server">server</a>
        </h3>
      </div>
      <ul className="doc-plugin-card__list">
        <li><a href="plugin-reference/server#udp_server">udp_server</a></li>
        <li><a href="plugin-reference/server#tcp_server">tcp_server</a></li>
        <li><a href="plugin-reference/server#quic_server">quic_server</a></li>
        <li><a href="plugin-reference/server#http_server">http_server</a></li>
      </ul>
    </section>

    <section className="doc-plugin-card">
      <div className="doc-plugin-card__header">
        <div className="doc-plugin-card__eyebrow">执行层</div>
        <h3 className="doc-plugin-card__title">
          <a href="plugin-reference/executor">executor</a>
        </h3>
      </div>
      <ul className="doc-plugin-card__list">
        <li><a href="plugin-reference/executor#sequence">sequence</a></li>
        <li><a href="plugin-reference/executor#forward">forward</a></li>
        <li><a href="plugin-reference/executor#cache">cache</a></li>
        <li><a href="plugin-reference/executor#fallback">fallback</a></li>
        <li><a href="plugin-reference/executor#hosts">hosts</a></li>
        <li><a href="plugin-reference/executor#arbitrary">arbitrary</a></li>
        <li><a href="plugin-reference/executor#redirect">redirect</a></li>
        <li><a href="plugin-reference/executor#reverse_lookup">reverse_lookup</a></li>
        <li><a href="plugin-reference/executor#ecs_handler">ecs_handler</a></li>
        <li><a href="plugin-reference/executor#forward_edns0opt">forward_edns0opt</a></li>
        <li><a href="plugin-reference/executor#ttl-1">ttl</a></li>
        <li><a href="plugin-reference/executor#prefer_ipv4-prefer_ipv6">prefer_ipv4</a></li>
        <li><a href="plugin-reference/executor#prefer_ipv4-prefer_ipv6">prefer_ipv6</a></li>
        <li><a href="plugin-reference/executor#black_hole">black_hole</a></li>
        <li><a href="plugin-reference/executor#drop_resp">drop_resp</a></li>
        <li><a href="plugin-reference/executor#sleep">sleep</a></li>
        <li><a href="plugin-reference/executor#debug_print">debug_print</a></li>
        <li><a href="plugin-reference/executor#download">download</a></li>
        <li><a href="plugin-reference/executor#reload">reload</a></li>
        <li><a href="plugin-reference/executor#query_summary">query_summary</a></li>
        <li><a href="plugin-reference/executor#metrics_collector">metrics_collector</a></li>
        <li><a href="plugin-reference/executor#ipset">ipset</a></li>
        <li><a href="plugin-reference/executor#nftset">nftset</a></li>
        <li><a href="plugin-reference/executor#ros_address_list">ros_address_list</a></li>
      </ul>
    </section>
  </div>
  <div className="doc-plugin-grid__column">
    <section className="doc-plugin-card">
      <div className="doc-plugin-card__header">
        <div className="doc-plugin-card__eyebrow">判断层</div>
        <h3 className="doc-plugin-card__title">
          <a href="plugin-reference/matcher">matcher</a>
        </h3>
      </div>
      <ul className="doc-plugin-card__list">
        <li><a href="plugin-reference/matcher#true">_true</a></li>
        <li><a href="plugin-reference/matcher#false">_false</a></li>
        <li><a href="plugin-reference/matcher#qname">qname</a></li>
        <li><a href="plugin-reference/matcher#qtype">qtype</a></li>
        <li><a href="plugin-reference/matcher#qclass">qclass</a></li>
        <li><a href="plugin-reference/matcher#client_ip">client_ip</a></li>
        <li><a href="plugin-reference/matcher#resp_ip">resp_ip</a></li>
        <li><a href="plugin-reference/matcher#ptr_ip">ptr_ip</a></li>
        <li><a href="plugin-reference/matcher#cname">cname</a></li>
        <li><a href="plugin-reference/matcher#mark">mark</a></li>
        <li><a href="plugin-reference/matcher#env">env</a></li>
        <li><a href="plugin-reference/matcher#random">random</a></li>
        <li><a href="plugin-reference/matcher#rate_limiter">rate_limiter</a></li>
        <li><a href="plugin-reference/matcher#rcode">rcode</a></li>
        <li><a href="plugin-reference/matcher#has_resp">has_resp</a></li>
        <li><a href="plugin-reference/matcher#has_wanted_ans">has_wanted_ans</a></li>
        <li><a href="plugin-reference/matcher#string_exp">string_exp</a></li>
      </ul>
    </section>

    <section className="doc-plugin-card">
      <div className="doc-plugin-card__header">
        <div className="doc-plugin-card__eyebrow">数据层</div>
        <h3 className="doc-plugin-card__title">
          <a href="plugin-reference/provider">provider</a>
        </h3>
      </div>
      <ul className="doc-plugin-card__list">
        <li><a href="plugin-reference/provider#domain_set">domain_set</a></li>
        <li><a href="plugin-reference/provider#ip_set">ip_set</a></li>
      </ul>
    </section>
  </div>
</div>
