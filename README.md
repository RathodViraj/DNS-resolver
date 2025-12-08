# DNS Resolver (simple iterative resolver)

## Overview — what DNS is and why it's distributed

The Domain Name System (DNS) maps human-friendly domain names (for example `example.com`) to machine-readable addresses (for example IPv4 or IPv6 addresses). DNS is a hierarchical, distributed database with multiple authoritative servers for each zone. When a client performs a lookup, that query can be resolved by contacting one or more DNS servers in a sequence until an authoritative answer is obtained.

Distributing DNS across many servers and operators avoids a single point of failure. Instead of relying on one server to answer all queries for a name, DNS uses:

- multiple authoritative name servers for each zone (NS records),
- root and TLD servers to bootstrap delegation,
- caching and recursion performed by resolvers to reduce load and latency.

This distribution improves resilience, reduces latency by using closer servers, and enables redundancy when some servers are unreachable.

## This project — what it is

This repository contains a minimal iterative DNS resolver implemented in Go. The resolver accepts UDP DNS queries from clients and resolves them by performing iterative queries to upstream servers (starting from configured root servers and following NS delegations). The code is intended for learning and debugging rather than production use.

Key behaviors:

- Iterative resolution: the resolver queries upstream servers, follows referrals (NS records), uses glue (additional) records when present, and falls back to resolving nameserver hostnames when no glue records are available.
- Caching: a small cache (implemented in `resolver/cache`) stores recent responses to reduce repeated network traffic.
- Server preference: servers that respond successfully are preferred for subsequent queries.
- Logging and metrics: the resolver logs upstream activity and records simple metrics for each query: total response time and number of recursive steps.

## Code structure and high-level flow

Files of interest:

- `main.go` — the program entrypoint and core resolver logic.
- `resolver/cache` — a package used to store and retrieve cached responses.

Important functions and their roles (all found in `main.go`):

- `main()`
  - Parses flags: `-listen` (address:port to bind to, default `:53`) and `-debug` (enable debug logging).
  - Starts a UDP listener and dispatches incoming packets to `HandlePacket`.

- `HandlePacket(...)` / `handlePacketInternal(...)`
  - Accepts a single UDP DNS packet, parses the query, and calls the resolver logic.
  - Measures request duration and logs metrics.
  - Uses the cache (`cache.GetFromCache` / `cache.SaveToCache`) when available.
  - Ensures the client receives a properly formed DNS response with the question section present and appropriate RCode.

- `dnsQuery(servers []net.IP, que dnsmessage.Question) (*dnsmessage.Message, int, error)`
  - Implements the iterative resolver logic.
  - Tries the provided `servers` list (IP addresses), sends the question, and inspects answers, authorities, and additionals.
  - Collects A/AAAA answers and follows CNAME chains when necessary.
  - When referrals are returned, it extracts NS records and any glue (A/AAAA records in the additionals) and switches to those IPs.
  - If no glue is present, it resolves NS hostnames (A/AAAA) by performing additional queries (these additional queries are counted as recursive steps).
  - Tracks and returns a step count (number of upstream queries performed) alongside the final response.

- `outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, net.IP, error)`
  - Sends the DNS question to the list of IP servers with small retries and timeouts.
  - Builds and returns a `dnsmessage.Message` parsed from the upstream response including `Answers`, `Authorities`, and `Additionals`.
  - Returns the IP of the server that produced the response so `dnsQuery` can prefer that server later.

- `getDNSServers()` returns the configured list of root server IPs (hardcoded in `ROOT_SERVERS`).

- `normalizeDNSName()` normalizes names used during glue matching.

## Instrumentation added

The resolver records two simple metrics per client query and logs them when responding:

- Query response time: how long it took from receiving the client query to sending the reply.
- Number of recursive steps: how many upstream queries the resolver issued while resolving the domain (this includes queries to resolve NS hostnames when needed).

These metrics are logged in `handlePacketInternal` as a single line like:

```
Query metrics: name=example.com type=A duration=12.345ms recursive_steps=3
```

This information helps identify slow lookups and domains that require multiple external queries.

## Running the resolver

Notes:
- Listening on UDP port `53` typically requires elevated privileges (root/Administrator).
- The code is written in Go and requires a working Go toolchain (Go 1.20+ recommended).

### Run

```cmd
go run path/../main.go
```
### Query the resolver (example using `dig`)

Point `dig` at the resolver and request records:

```bash
dig @127.0.0.1 example.com
```

## Notes, limitations, and suggestions

- This resolver is educational and not hardened for production use. It lacks DNSSEC validation, rate limiting, concurrency controls for large loads, robust error handling for all corner cases, and advanced caching policies.
- The resolver is iterative (non-recursive): it performs the iterative steps itself and returns the final answer to the client.
