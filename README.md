# Iwinswap DeFi State Client

This Go application serves as a client for the Iwinswap DeFi State Engine. It connects to the engine's JSON-RPC endpoint to receive and process real-time DeFi protocol state updates.The client is pre-configured with all the necessary patchers and copiers to handle state diffs for multiple DeFi protocols, including Uniswap V2, Uniswap V3, and various token/pool systems.

## Getting Started

To run the client, you only need to provide the URL of your DeFi State Engine.

### Prerequisites
- Go (Golang) installed.
- Access to a running DeFi State Engine JSON-RPC (or WebSocket) endpoint.

### Installation

1. Clone the client repo:
    `git clone https://github.com/Iwinswap/iwinswap-defi-state-client-go`

2. Install dependencies:
    `go mod tidy`


### Running the Client

You can build the application or run it directly. The only required argument is the -state-engine-url.

`go run main.go -state-engine-url wss://your-state-engine-endpoint.com
`





