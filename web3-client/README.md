# web3-client

Unified entry + adapter registry.

## Components
- `Web3Client` — facade over `ChainAdapterRegistry`
- `ChainAdapterRegistry` — manages `ChainType -> ChainAdapter` mapping, supports ServiceLoader auto-discovery

## Usage
```java
Web3Client client = Web3Client.builder()
    .autoDiscover()   // or register(new EvmChainAdapter())
    .build();

boolean supported = client.supports(ChainType.EVM);
ChainAdapter<?, ?> adapter = client.adapter(ChainType.EVM);
```

SPI file name: `META-INF/services/io.github.superedison.web3.chain.spi.ChainAdapter`
