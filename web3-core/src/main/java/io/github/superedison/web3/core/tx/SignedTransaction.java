package io.github.superedison.web3.core.tx;

public interface SignedTransaction<TX extends RawTransaction> {
    /**
     * 原始交易（已填充签名相关字段）
     */
    TX rawTransaction();

    /**
     * 可广播的原始字节（最终序列化结果）
     * <p>
     * - 由 chain 层 encoder 生成
     * - 建议实现类缓存该值
     */
    byte[] rawBytes();

    /**
     * 交易哈希（txHash）
     * <p>
     * - 由链协议定义
     * - 通常用于查询、回执、广播确认
     */
    byte[] txHash();

    /**
     * 交易发起者地址（from）
     * <p>
     * - 纯展示 / 索引用途
     * - 不参与签名逻辑
     */
    String from();
}
