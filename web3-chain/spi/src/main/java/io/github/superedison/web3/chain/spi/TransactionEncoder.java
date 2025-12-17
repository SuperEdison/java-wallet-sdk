package io.github.superedison.web3.chain.spi;

import io.github.superedison.web3.core.tx.RawTransaction;

/**
 * 交易编码器 SPI：把原始意图编码成待签名字节。
 *
 * @param <TX> 原始交易类型
 */
public interface TransactionEncoder<TX extends RawTransaction> {

    /**
     * 编码交易（用于签名或广播）。
     *
     * @param transaction 原始交易
     * @return 编码后的字节数组
     */
    byte[] encode(TX transaction);
}
