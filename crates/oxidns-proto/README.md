# oxidns-proto

`oxidns-proto` contains the DNS message model and wire codec primitives used
by OxiDNS.

It is split out as a standalone crate so the DNS protocol layer can evolve
independently from the full server runtime.
