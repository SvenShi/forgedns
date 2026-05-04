import type { PluginInstance } from "@/lib/types";
import type { PluginComponentDefinition } from "./types";
import { udpPlugin } from "./kinds/udp";
import { tcpPlugin } from "./kinds/tcp";
import { dohPlugin } from "./kinds/doh";
import { dotPlugin } from "./kinds/dot";
import { cachePlugin } from "./kinds/cache";
import { forwardPlugin } from "./kinds/forward";
import { blockPlugin } from "./kinds/block";
import { rewritePlugin } from "./kinds/rewrite";
import { parallelPlugin } from "./kinds/parallel";
import { domainListPlugin } from "./kinds/domain-list";
import { ipListPlugin } from "./kinds/ip-list";
import { regexPlugin } from "./kinds/regex";
import { geoipPlugin } from "./kinds/geoip";
import { queryTypePlugin } from "./kinds/query-type";
import { hostsPlugin } from "./kinds/hosts";
import { redisPlugin } from "./kinds/redis";
import { filePlugin } from "./kinds/file";
import { prometheusPlugin } from "./kinds/prometheus";
import { httpPlugin } from "./kinds/http";
import { sequencePlugin } from "./kinds/sequence";

// Optional card/detail overrides live here. If a kind is omitted or exports an
// empty definition, the plugin center falls back to the generic templates.
export const pluginComponentRegistry: Record<
  string,
  PluginComponentDefinition
> = {
  sequence: sequencePlugin,
  udp: udpPlugin,
  tcp: tcpPlugin,
  doh: dohPlugin,
  dot: dotPlugin,
  cache: cachePlugin,
  forward: forwardPlugin,
  block: blockPlugin,
  rewrite: rewritePlugin,
  parallel: parallelPlugin,
  domain_list: domainListPlugin,
  ip_list: ipListPlugin,
  regex: regexPlugin,
  geoip: geoipPlugin,
  query_type: queryTypePlugin,
  hosts: hostsPlugin,
  redis: redisPlugin,
  file: filePlugin,
  prometheus: prometheusPlugin,
  http: httpPlugin,
};

export function getPluginComponentDefinition(plugin: PluginInstance) {
  return pluginComponentRegistry[plugin.pluginKind];
}
