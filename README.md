# ark-node

[![Go Version](https://img.shields.io/badge/Go-1.23.1-blue.svg)](https://golang.org/doc/go1.23)
[![GitHub Release](https://img.shields.io/github/v/release/ArkLabsHQ/ark-node)](https://github.com/ArkLabsHQ/ark-node/releases/latest)
[![License](https://img.shields.io/github/license/ArkLabsHQ/ark-node)](https://github.com/ArkLabsHQ/ark-node/blob/main/LICENSE)
[![Docker Image](https://img.shields.io/docker/pulls/arklabshq/ark-node)](https://ghcr.io/arklabshq/ark-node)
[![GitHub Stars](https://img.shields.io/github/stars/ArkLabsHQ/ark-node)](https://github.com/ArkLabsHQ/ark-node/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/ArkLabsHQ/ark-node)](https://github.com/ArkLabsHQ/ark-node/issues)

Ark Node is a Bitcoin wallet daemon that integrates Ark protocol's batched transaction model with Lightning Network infrastructure, enabling routing nodes, service providers and payment hubs to optimize channel liquidity while minimizing on-chain fees, without compromising on self-custody.

## 🚀 Usage

### 🐳 Using Docker (Recommended)

The easiest way to run ark-node is using Docker. Make sure you have [Docker](https://docs.docker.com/get-docker/) installed on your machine.

```bash
docker run -d \
  --name ark-node \
  -p 7000:7000 \
  -p 7001:7001 \
  -v ark-node-data:/app/data \
  ghcr.io/arklabshq/ark-node:latest
```

Once the container is running, you can access the web UI at [http://localhost:7001](localhost:7001).

To view logs:

```bash
docker logs -f ark-node
```

To stop the container:

```bash
docker stop ark-node
```

### 💻 Using the Binary

Alternatively, you can download the latest release from the [releases page](https://github.com/ArkLabsHQ/ark-node/releases) for your platform. After downloading:

1. Extract the binary
2. Make it executable (on Linux/macOS): `chmod +x ark-node`
3. Run the binary: `./ark-node`

### 🔧 Environment Variables

The following environment variables can be configured:

| Variable | Description | Default |
|----------|-------------|---------|
| `ARK_NODE_DATADIR` | Directory to store wallet data | `/app/data` in Docker, `~/.ark-node` otherwise |
| `ARK_NODE_HTTP_PORT` | HTTP port for the web UI and REST API | `7001` |
| `ARK_NODE_GRPC_PORT` | gRPC port for service communication | `7002` |
| `ARK_NODE_ARK_SERVER` | URL of the Ark server to connect to | It pre-fills with the default Ark server |

When using Docker, you can set these variables using the `-e` flag:

```bash
docker run -d \
  --name ark-node \
  -p 7001:7001 \
  -e ARK_NODE_HTTP_PORT=7001 \
  -e ARK_NODE_ARK_SERVER="https://server.example.com" \
  -v ark-node-data:/app/data \
  ghcr.io/arklabshq/ark-node:latest
```

## 👨‍💻 Development

To get started with ark-node development you need Go `1.23.1` or higher and Node.js `18.17.1` or higher.

```bash
git clone https://github.com/ArkLabsHQ/ark-node.git
cd ark-node
go mod download
make run
```

Now navigate to [http://localhost:7001/](http://localhost:7001/) to see the dashboard.

## 🤝 Contributing

We welcome contributions to ark-node! Here's how you can help:

1. **Fork the repository** and create your branch from `main`
2. **Install dependencies**: `go mod download`
3. **Make your changes** and ensure tests pass: `make test`
4. **Run the linter** to ensure code quality: `make lint`
5. **Submit a pull request**

For major changes, please open an issue first to discuss what you would like to change.

### 🛠️ Development Commands

The Makefile contains several useful commands for development:

- `make run`: Run in development mode
- `make build`: Build the binary for your platform
- `make test`: Run unit tests
- `make lint`: Lint the codebase
- `make proto`: Generate protobuf stubs (requires Docker)

## 📚 API Documentation

### 🔌 API Interfaces

ark-node provides two main interfaces:

1. **Web UI** - Available at [http://localhost:7001](http://localhost:7001) by default
2. **API Services** - Both REST and gRPC interfaces

The REST API is accessible at the same port as the Web UI, while the gRPC service runs on a separate port (default: 7002).

Here's a high-level overview of the main API endpoints, including examples using curl:

### 💰 Wallet Service

1. Generate Seed

   ```sh
   curl -X GET http://localhost:7001/api/v1/wallet/genseed
   ```

2. Create Wallet

   Password must:
   - Be 8 chars or longer
   - Have at least one number
   - Have at least one special char

   Private key supported formats:
   - 64 chars hexadecimal
   - Nostr nsec (NIP-19)
  
   ```sh
   curl -X POST http://localhost:7001/api/v1/wallet/create \
        -H "Content-Type: application/json" \
        -d '{"private_key": <hex or nsec>, "password": <strong password>, "server_url": "https://server.example.com"}'
   ```

3. Unlock Wallet

   ```sh
   curl -X POST http://localhost:7001/api/v1/wallet/unlock \
        -H "Content-Type: application/json" \
        -d '{"password": <strong password>}'
   ```

4. Lock Wallet

   ```sh
   curl -X POST http://localhost:7001/api/v1/wallet/lock \
        -H "Content-Type: application/json" \
        -d '{"password": <strong password>}'
   ```

5. Get Wallet Status

   ```sh
   curl -X GET http://localhost:7001/api/v1/wallet/status
   ```

### ⚡ Service API

1. Get Address

   ```sh
   curl -X GET http://localhost:7001/api/v1/address
   ```

2. Get Balance

   ```sh
   curl -X GET http://localhost:7001/api/v1/balance
   ```

3. Send funds offchain

   ```sh
   curl -X POST http://localhost:7001/api/v1/send/offchain \
        -H "Content-Type: application/json" \
        -d '{"address": <ark address>, "amount": <in sats>}'
   ```

4. Send funds onchain

   ```sh
   curl -X POST http://localhost:7001/api/v1/send/onchain \
        -H "Content-Type: application/json" \
        -d '{"address": <bitcoin address>, "amount": <in sats>}'
   ```

5. Get transaction history

   ```sh
   curl -X GET http://localhost:7001/api/v1/transactions
   ```

### 🔔 Notification Service

1. Add Webhook

   ```sh
   curl -X POST http://localhost:7001/api/v1/notifications/webhook \
        -H "Content-Type: application/json" \
        -d '{"endpoint": "https://your-webhook.com/endpoint", "event_type": "WEBHOOK_EVENT_TYPE_ROUND", "secret": "your_secret"}'
   ```

2. Remove Webhook

   ```sh
   curl -X DELETE http://localhost:7001/api/v1/notifications/webhook/{webhook_id}
   ```

3. List Webhooks

   ```sh
   curl -X GET http://localhost:7001/api/v1/notifications/webhooks
   ```

Note: Replace `http://localhost:7001` with the appropriate host and port where your ark-node is running. Also, ensure to replace placeholder values (like `strong password`, `ark_address`, etc.) with actual values when making requests.

For more detailed information about request and response structures, please refer to the proto files in the `api-spec/protobuf/ark_node/v1/` directory.
