package io.github.superedison.web3.chain.evm.internal;

import io.github.superedison.web3.chain.spi.TransactionHasher;
import io.github.superedison.web3.crypto.hash.Keccak256;

/**
 * EVM 交易哈希（Keccak256）。
 */
public final class EvmTransactionHasher implements TransactionHasher {

    @Override
    public byte[] hash(byte[] encodedTx) {
        return Keccak256.hash(encodedTx);
    }
}
