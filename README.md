# rocked

Fast tunneling tool built in Rust. Expose local servers to the public internet with a single command.

```
$ rocked http 8080
  tunnel ready: https://abc123.tunn.uz
```

## Install

```bash
curl -s https://tunn.uz/install | bash
```

Or download binaries from [Releases](https://github.com/Diyarbekoralbaev/rocked-public/releases).

## Usage

```bash
# Expose a local HTTP server
rocked http 8080

# Expose a TCP port (databases, SSH, etc.)
rocked tcp 5432

# Expose a UDP port
rocked udp 9000

# Custom server
rocked --server wss://your-server.com/ws http 3000
```

## How it works

```
[local :8080] ←→ [rocked client] ←WebSocket→ [rocked server] ←→ [public internet]
```

The client opens a WebSocket connection to the server, which assigns a public subdomain. Incoming traffic is relayed through the WebSocket tunnel to your local port. All traffic is TLS-encrypted.

## Build from source

```bash
cargo build --release -p rocked-client
```

## License

MIT
