package io.github.superedison.web3.chain.spi;

/**
 * 交易哈希器：对编码后的交易字节求哈希（供签名与 txHash 使用）。
 */
public interface TransactionHasher {

    /**
     * 计算交易哈希。
     *
     * @param encodedTx 已编码交易字节
     * @return 32 字节哈希结果
     */
    byte[] hash(byte[] encodedTx);
}
