package io.github.superedison.web3.chain.solana.internal;

import io.github.superedison.web3.chain.spi.TransactionHasher;

/**
 * Solana 交易哈希计算器
 *
 * Solana 的交易 ID 就是第一个签名的 Base58 编码
 * 但为了与其他链保持一致，这里返回签名的原始字节
 */
public final class SolanaTransactionHasher implements TransactionHasher {

    @Override
    public byte[] hash(byte[] data) {
        // Solana 的交易哈希就是签名本身
        // 在签名完成后，txHash 直接使用签名
        // 这里主要用于消息签名前的处理
        return data;
    }
}
