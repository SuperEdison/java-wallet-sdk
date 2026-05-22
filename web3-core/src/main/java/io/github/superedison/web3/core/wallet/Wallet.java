package io.github.superedison.web3.core.wallet;

import io.github.superedison.web3.core.signer.Signer;

import java.util.Optional;

/**
 * 钱包接口。
 *
 * 一个钱包总是有 {@link #getAddress()} 和 {@link #getSigner()}，
 * 但 {@link #getKeyHolder()} 是可选的——
 *   - 本地钱包：返回 {@code Optional.of(localKeyHolder)}，可走 {@code exportPrivateKey()}
 *   - KMS / HSM / 硬件钱包：返回 {@link Optional#empty()}，因为远程密钥根本不存在可导出的字节
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
     * 获取密钥持有者。仅本地钱包返回非空——远程托管（KMS / HSM）密钥没有可导出的字节，返回 {@link Optional#empty()}。
     */
    Optional<KeyHolder> getKeyHolder();

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
