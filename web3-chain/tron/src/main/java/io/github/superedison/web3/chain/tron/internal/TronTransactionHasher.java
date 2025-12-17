package io.github.superedison.web3.chain.tron.internal;

import io.github.superedison.web3.chain.spi.TransactionHasher;
import io.github.superedison.web3.crypto.hash.Sha256;

/**
 * TRON 交易哈希：txid = SHA256(raw_data)。
 */
public final class TronTransactionHasher implements TransactionHasher {

    @Override
    public byte[] hash(byte[] encodedTx) {
        return Sha256.hash(encodedTx);
    }
}
