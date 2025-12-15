package io.github.superedison.web3.core.transaction;

import io.github.superedison.web3.core.signer.Signature;

/**
 * 已签名交易接口
 */
public interface SignedTransaction {

    /**
     * 获取原始交易
     */
    RawTransaction getRawTransaction();

    /**
     * 获取签名
     */
    Signature getSignature();

    /**
     * 获取签名者地址
     */
    String getFrom();

    /**
     * 获取交易哈希 (txHash)
     */
    byte[] getTransactionHash();

    /**
     * 序列化为字节（用于广播）
     */
    byte[] encode();

    /**
     * 验证签名是否有效
     */
    boolean isValid();
}