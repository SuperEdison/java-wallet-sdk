package io.github.superedison.web3.chain.btc.internal;

import io.github.superedison.web3.chain.spi.TransactionHasher;
import io.github.superedison.web3.crypto.hash.Sha256;

/**
 * Bitcoin 交易哈希计算器
 *
 * Bitcoin 使用双重 SHA-256 哈希
 */
public final class BtcTransactionHasher implements TransactionHasher {

    @Override
    public byte[] hash(byte[] data) {
        return Sha256.doubleHash(data);
    }

    /**
     * 计算交易 ID (不包含 witness 数据的哈希)
     */
    public byte[] computeTxid(byte[] txDataWithoutWitness) {
        return Sha256.doubleHash(txDataWithoutWitness);
    }

    /**
     * 计算 witness 交易 ID (包含 witness 数据的哈希)
     */
    public byte[] computeWtxid(byte[] txDataWithWitness) {
        return Sha256.doubleHash(txDataWithWitness);
    }
}
