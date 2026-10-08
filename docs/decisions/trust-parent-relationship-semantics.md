# Trust parent relationship semantics

Structural IOC parentage uses connector-owned `related-to` edges:

```text
child --related-to [IOC trust-cluster structural parent link (auto-created)]--> parent
```

OpenCTI rejects `belongs-to` for the current SCO parentage pairs (`Domain-Name→Domain-Name`, `Url→Domain-Name`, `Url→IPv4-Addr`, `IPv4-Addr→IPv4-Addr`), so `related-to` is canonical for those trust-parent edges.

`belongs-to` is used only where OpenCTI allows ownership semantics, currently CIDR → `Autonomous-System`.

Legacy structural `trust-cluster:<parent>` labels are not source of truth; relationships are.
