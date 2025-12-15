package io.github.superedison.web3.core.wallet;

/**
 * 密钥持有者接口
 * 抽象私钥持有方式，支持明文/MPC/HSM
 */
public interface KeyHolder {

    /**
     * 获取公钥
     */
    byte[] getPublicKey();

    /**
     * 获取地址
     */
    Address getAddress();

    /**
     * 是否可导出私钥
     */
    boolean canExportPrivateKey();

    /**
     * 导出私钥（如不支持抛异常）
     */
    byte[] exportPrivateKey();

    /**
     * 销毁密钥
     */
    void destroy();

    /**
     * 是否已销毁
     */
    boolean isDestroyed();
}