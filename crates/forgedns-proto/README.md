# forgedns-proto

`forgedns-proto` contains the DNS message model and wire codec primitives used
by ForgeDNS.

It is split out as a standalone crate so the DNS protocol layer can evolve
independently from the full server runtime.
