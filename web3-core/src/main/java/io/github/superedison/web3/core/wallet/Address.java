package io.github.superedison.web3.core.wallet;

/**
 * 地址接口
 */
public interface Address {

    /**
     * 获取地址字符串
     */
    String toBase58();

    /**
     * 获取地址字节
     */
    byte[] toBytes();

    /**
     * 验证地址有效性
     */
    boolean isValid();
}