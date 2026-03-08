# tunn

Fast tunneling tool built in Rust. Expose local servers to the public internet with a single command.

```
$ tunn http 8080
  tunnel ready: https://abc123.tunn.uz
```

## Install

```bash
curl -s https://tunn.uz/install | bash
```

Or download binaries from [Releases](https://github.com/Diyarbekoralbaev/tunn/releases).

## Usage

```bash
# Expose a local HTTP server
tunn http 8080

# Expose a TCP port (databases, SSH, etc.)
tunn tcp 5432

# Expose a UDP port
tunn udp 9000
```

## How it works

```
[local :8080] <-> [tunn client] <-QUIC-> [tunn server] <-> [public internet]
```

The client opens a QUIC connection to the server, which assigns a public subdomain. Incoming traffic is relayed through the encrypted tunnel to your local port.

## Build from source

```bash
cargo build --release -p tunn
```

## License

MIT
