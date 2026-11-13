# tcpfp

A server that records what a website sees at the TCP/IP layer when a client connects through a
proxy. Through a CONNECT proxy the TLS and HTTP come from the client, but the TCP handshake
comes from the proxy's exit node. tcpfp captures that handshake, adds IP and ASN data, and
stores it, so proxies can be screened before they go into a pool.

## How it works

```
client --CONNECT--> proxy exit node
                           |
                          SYN
                           v
                   :443 on the host
                   |                 |
                   v                 v
          AF_PACKET capture     front proxy
                   |                 |
                   v                 |  PROXY protocol v2
         SYN store (ip:port)         |
                   |                 v
                   +-------> tcpfp HTTP handler
                                     |
                                     v
                         fingerprint and features
                           |-> ip-api.com reputation
                           |-> ClickHouse (/index)
                           '-> Elasticsearch (/details?infer)
```

- **Capture:** an AF_PACKET raw socket through `pnet` on the host interface, keeping IPv4 SYNs to
  the capture port (`src/packets.rs`). Needs `CAP_NET_RAW` and host networking.
- **Matching a request to its SYN:** the sniffer publishes each SYN into an LRU keyed by source
  ip:port; the HTTP handler waits for its key (`src/store.rs`). Keep-alive is off, so every
  request opens a fresh connection with a fresh SYN.
- **Behind a front proxy:** with `TCPFP_PROXY_PROTOCOL=true` every connection must start with a
  PROXY protocol v2 header carrying the real client address (`src/proxy_protocol.rs`); connections without
  a valid one are dropped. TLS is terminated by tcpfp with rustls and certificate hot-reload.
- **Features** (`src/fingerprints/`): initial TTL and hop count, window size and scaling, TCP
  option order, MSS and derived MTU, timestamps, SACK, DF and other IP header fields.
- **Reputation** (`src/reputation.rs`): ip-api.com (ASN, ISP, org, proxy, mobile and hosting flags),
  cached for 10 minutes. Lookup failures are logged; clients only see that the lookup failed.
- **Scoring** (`src/inference.rs`): `/details?infer=<model_id>` sends the feature document to an Elasticsearch trained
  model (`_ml/trained_models/<id>/_infer`) and returns the class probabilities. Training is not in
  this repository.

## Endpoints

| Path | Returns |
|---|---|
| `/fingerprint` | IP and TCP fingerprint and derived features |
| `/details` | the above plus reputation; `?infer=<model_id>` adds the model score |
| `/index?p=<proxy>` | stores the check in ClickHouse, returns a request id; `p` is the proxy string in URL-safe base64 without padding |
| `/lookup?ipv4=` | which proxy providers an IP was seen with |
| `/metrics` | service metrics |

## Running

```
cp .env.example .env   # fill in CLICKHOUSE_PASSWORD, TCPFP_IPAPI_KEY, the certificate paths
docker compose up -d
```

`compose.yml` runs ClickHouse, the `dbmate` migrations and two instances: plain HTTP on :80, and
HTTPS on 127.0.0.1:8081 behind a front proxy that owns :443 and speaks PROXY protocol v2 (the
front proxy itself is not part of this repository). Both use the host's network namespace and
`CAP_NET_RAW`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TCPFP_BIND` | `0.0.0.0` | listen address |
| `TCPFP_PORT` | 80, or 443 with TLS | listen port |
| `TCPFP_CAPTURE_PORT` | `TCPFP_PORT` | port whose SYNs are captured |
| `TCPFP_INTERFACE` | first up, non-loopback interface with IPv4 | interface to capture on |
| `TCPFP_SECURE` | `false` | serve HTTPS |
| `TCPFP_CERT`, `TCPFP_KEY` | | certificate chain and key (PEM) for HTTPS |
| `TCPFP_PROXY_PROTOCOL` | `false` | require a PROXY protocol v2 header on every connection |
| `TCPFP_STORE_SIZE` | 128 | SYNs kept while their requests arrive |
| `TCPFP_IPAPI_KEY` | | ip-api.com Pro key |
| `TCPFP_ES_URL`, `TCPFP_ES_API_KEY` | | Elasticsearch for `/details?infer` |
| `TCPFP_CLICKHOUSE_URL` | `http://localhost:18123` | ClickHouse for `/index` and `/lookup` |
| `TCPFP_CLICKHOUSE_PASSWORD` | | its password |

With compose, the per-instance settings are in `compose.yml` and the rest in `.env`.

## Known limits

- IPv4 only.
- No in-kernel BPF filter; filtering happens in user space.
- If capturing fails the process exits, so its supervisor can restart it.
- Only the SYN is used: no SYN-ACK timing and no OS classification in the server itself.
- The Elasticsearch client skips certificate validation.
