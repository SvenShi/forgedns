---
title: ForgeDNS
sidebar_position: 1
slug: /
---

This documentation explains ForgeDNS configuration, plugin composition, management APIs, common policy patterns, and the project architecture.

Recommended reading order:

1. Read [Quick Start](quickstart.md) to choose an installation path and complete the first successful start.
2. Read [Configuration Overview](configuration.md) to understand the top-level YAML layout and `sequence` orchestration model.
3. Read [Plugin Overview](plugin-reference/overview.md) and then the four plugin categories: `server`, `executor`, `matcher`, and `provider`.
4. Read [Management API](api.md) when integrating ForgeDNS with control planes, dashboards, or automation.
5. Read [Common Scenarios](scenarios.md) for policy composition patterns.
6. Read [Architecture and Design](architecture-and-design.md) and [Benchmarks](benchmarks.md) for implementation background and performance direction.

## Scope

ForgeDNS ships with the following built-in plugin families:

<div className="doc-plugin-grid">
  <div className="doc-plugin-grid__column">
    <section className="doc-plugin-card">
      <div className="doc-plugin-card__header">
        <div className="doc-plugin-card__eyebrow">Ingress</div>
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
        <div className="doc-plugin-card__eyebrow">Execution</div>
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
        <li><a href="plugin-reference/executor#ttl">ttl</a></li>
        <li><a href="plugin-reference/executor#prefer_ipv4-and-prefer_ipv6">prefer_ipv4 / prefer_ipv6</a></li>
        <li><a href="plugin-reference/executor#black_hole">black_hole</a></li>
        <li><a href="plugin-reference/executor#drop_resp">drop_resp</a></li>
        <li><a href="plugin-reference/executor#sleep">sleep</a></li>
        <li><a href="plugin-reference/executor#debug_print">debug_print</a></li>
        <li><a href="plugin-reference/executor#query_summary">query_summary</a></li>
        <li><a href="plugin-reference/executor#metrics_collector">metrics_collector</a></li>
        <li><a href="plugin-reference/executor#ipset">ipset</a></li>
        <li><a href="plugin-reference/executor#nftset">nftset</a></li>
        <li><a href="plugin-reference/executor#mikrotik">mikrotik</a></li>
      </ul>
    </section>
  </div>
  <div className="doc-plugin-grid__column">
    <section className="doc-plugin-card">
      <div className="doc-plugin-card__header">
        <div className="doc-plugin-card__eyebrow">Matching</div>
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
        <div className="doc-plugin-card__eyebrow">Data</div>
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
