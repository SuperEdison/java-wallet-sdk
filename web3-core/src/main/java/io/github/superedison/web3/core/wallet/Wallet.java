package io.github.superedison.web3.core.wallet;

import io.github.superedison.web3.core.signer.Signer;

/**
 * 钱包接口
 */
public interface Wallet {

    /**
     * 获取钱包 ID
     */
    String getId();

    /**
     * 获取地址
     */
    Address getAddress();

    /**
     * 获取密钥持有者
     */
    KeyHolder getKeyHolder();

    /**
     * 获取签名器
     */
    Signer getSigner();

    /**
     * 销毁钱包
     */
    void destroy();

    /**
     * 是否已销毁
     */
    boolean isDestroyed();
}