package io.github.superedison.web3.core.signer;

import io.github.superedison.web3.core.wallet.Address;

/**
 * 签名器接口
 */
public interface Signer {

    /**
     * 获取签名算法
     */
    SignatureScheme getScheme();

    /**
     * 获取关联地址
     */
    Address getAddress();

    /**
     * 对数据哈希签名
     * @param hash 32字节哈希
     */
    Signature sign(byte[] hash);

    /**
     * 验证签名
     */
    boolean verify(byte[] hash, Signature signature);

    /**
     * 销毁签名器
     */
    void destroy();

    /**
     * 是否已销毁
     */
    boolean isDestroyed();
}