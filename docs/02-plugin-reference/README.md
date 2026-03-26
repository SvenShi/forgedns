# 插件总览

ForgeDNS 的插件可分为四层：

- `server`
  - 网络入口，负责监听与接入协议。
- `executor`
  - 执行动作，负责转发、缓存、重写、观测和系统联动。
- `matcher`
  - 条件判断，负责给 `sequence` 提供策略分支条件。
- `provider`
  - 数据提供，负责沉淀可复用规则集。

推荐阅读顺序如下：

1. 服务端插件：明确请求进入系统的方式。
2. 执行器插件：理解请求与响应的实际处理动作。
3. 匹配器插件：理解策略分流条件。
4. 数据提供器插件：理解共享规则集的组织方式。

在 ForgeDNS 中，复杂策略通常通过多类插件组合实现，而不是依赖单一插件完成全部行为：

```text
server -> sequence
  -> matcher 判断
  -> executor 执行
  -> provider 提供规则集
  -> upstream 或 side effect
```
