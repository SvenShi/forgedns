---
title: OxiDNS
sidebar_position: 1
slug: /
---

For first-time use, start with a minimal runnable setup, then choose the common scenario closest to the deployment goal and extend from there.

Recommended reading path:

1. Read [Quick Start](quickstart.md) to choose an installation path and complete the first successful start.
2. Read [Common Scenarios](scenarios.md) and choose the configuration closest to the deployment goal.
3. Read [Configuration Overview](configuration.md) to understand the top-level YAML layout, `include` splitting, and `sequence` orchestration.
4. Read [CLI Tools](cli.md) for daily commands such as `check`, `start`, `service`, `export-dat`, and `upgrade`.
5. For tuning a specific capability, read [Plugin Overview](plugin-reference/overview.md) and the relevant plugin category.
6. Read [WebUI Deployment](webui.md) when deploying the management console; read [Management API](api.md) when integrating scripts, platforms, or monitoring.
7. Read [Architecture and Design](architecture-and-design.md) and [Benchmarks](benchmarks.md) when evaluating performance or design trade-offs.

## Scope

The index below lists the built-in plugin families. In normal use, start from a scenario config first, then come back here to look up the fields and behavior of individual plugins.

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
        <li><a href="plugin-reference/server#http_server">http_server</a></li>
        <li><a href="plugin-reference/server#quic_server">quic_server</a></li>
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
        <li><a href="plugin-reference/executor#ecs_handler">ecs_handler</a></li>
        <li><a href="plugin-reference/executor#forward_edns0opt">forward_edns0opt</a></li>
        <li><a href="plugin-reference/executor#ttl">ttl</a></li>
        <li><a href="plugin-reference/executor#prefer_ipv4-prefer_ipv6">prefer_ipv4 / prefer_ipv6</a></li>
        <li><a href="plugin-reference/executor#black_hole">black_hole</a></li>
        <li><a href="plugin-reference/executor#drop_resp">drop_resp</a></li>
        <li><a href="plugin-reference/executor#reverse_lookup">reverse_lookup</a></li>
        <li><a href="plugin-reference/executor#query_summary">query_summary</a></li>
        <li><a href="plugin-reference/executor#query_recorder">query_recorder</a></li>
        <li><a href="plugin-reference/executor#metrics_collector">metrics_collector</a></li>
        <li><a href="plugin-reference/executor#debug_print">debug_print</a></li>
        <li><a href="plugin-reference/executor#sleep">sleep</a></li>
        <li><a href="plugin-reference/executor#http_request">http_request</a></li>
        <li><a href="plugin-reference/executor#script">script</a></li>
        <li><a href="plugin-reference/executor#ipset">ipset</a></li>
        <li><a href="plugin-reference/executor#nftset">nftset</a></li>
        <li><a href="plugin-reference/executor#ros_address_list">ros_address_list</a></li>
        <li><a href="plugin-reference/executor#upgrade">upgrade</a></li>
        <li><a href="plugin-reference/executor#download">download</a></li>
        <li><a href="plugin-reference/executor#reload_provider">reload_provider</a></li>
        <li><a href="plugin-reference/executor#reload">reload</a></li>
        <li><a href="plugin-reference/executor#cron">cron</a></li>
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
        <li><a href="plugin-reference/matcher#any_match">any_match</a></li>
        <li><a href="plugin-reference/matcher#qname">qname</a></li>
        <li><a href="plugin-reference/matcher#question">question</a></li>
        <li><a href="plugin-reference/matcher#qtype">qtype</a></li>
        <li><a href="plugin-reference/matcher#qclass">qclass</a></li>
        <li><a href="plugin-reference/matcher#client_ip">client_ip</a></li>
        <li><a href="plugin-reference/matcher#resp_ip">resp_ip</a></li>
        <li><a href="plugin-reference/matcher#ptr_ip">ptr_ip</a></li>
        <li><a href="plugin-reference/matcher#cname">cname</a></li>
        <li><a href="plugin-reference/matcher#rcode">rcode</a></li>
        <li><a href="plugin-reference/matcher#has_resp">has_resp</a></li>
        <li><a href="plugin-reference/matcher#has_wanted_ans">has_wanted_ans</a></li>
        <li><a href="plugin-reference/matcher#mark">mark</a></li>
        <li><a href="plugin-reference/matcher#env">env</a></li>
        <li><a href="plugin-reference/matcher#random">random</a></li>
        <li><a href="plugin-reference/matcher#rate_limiter">rate_limiter</a></li>
        <li><a href="plugin-reference/matcher#string_exp">string_exp</a></li>
        <li><a href="plugin-reference/matcher#true">_true</a></li>
        <li><a href="plugin-reference/matcher#false">_false</a></li>
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
        <li><a href="plugin-reference/provider#geosite">geosite</a></li>
        <li><a href="plugin-reference/provider#adguard_rule">adguard_rule</a></li>
        <li><a href="plugin-reference/provider#ip_set">ip_set</a></li>
        <li><a href="plugin-reference/provider#geoip">geoip</a></li>
      </ul>
    </section>
  </div>
</div>
