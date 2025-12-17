# web3-chain

Chain abstraction & SPI.

## Interfaces
- `ChainAdapter<TX extends RawTransaction, STX extends SignedTransaction<TX>>`
  - `ChainType chainType()`
  - `STX sign(TX tx, SigningKey key)` (encode -> hash -> sign -> assemble)
  - `byte[] rawBytes(STX signedTx)` (broadcast bytes)
  - `byte[] txHash(STX signedTx)` (chain-defined tx hash)
- `TransactionEncoder<TX extends RawTransaction>`
- `TransactionHasher`
- `TransactionSigner<TX, STX>` (optional helper)
- `ChainType` (planned chains, curve, default HD path)

## Red lines
- No wallet/mnemonic management
- No RPC / broadcast
- No UI-friendly helpers
- No chain-specific enums/constants in core

## SPI registration
`META-INF/services/io.github.superedison.web3.chain.spi.ChainAdapter` lists available adapters (see EVM module for example).
