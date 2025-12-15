package io.github.superedison.web3.core.transaction;

/**
 * 原始交易接口
 * 纯抽象，不定义具体字段
 */
public interface RawTransaction {

    /**
     * 获取交易类型
     */
    TransactionType getType();

    /**
     * 序列化为字节（用于签名）
     */
    byte[] encode();

    /**
     * 计算交易哈希（用于签名）
     */
    byte[] hash();
}