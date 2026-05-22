package io.github.superedison.web3.chain.tron.wallet;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.core.signer.Signer;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.KeyHolder;
import io.github.superedison.web3.core.wallet.Wallet;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.util.SecureBytes;

import java.util.Optional;

/**
 * TRON 钱包实现。
 *
 * 两种构造方式：
 * <ol>
 *   <li><b>本地钱包</b>：{@link #TronWallet(String, byte[], boolean)} —— SDK 拥有私钥字节，提供 KeyHolder（可选导出）和 Signer。
 *       钱包内部负责 destroy 私钥。</li>
 *   <li><b>远程钱包（KMS / HSM）</b>：{@link #TronWallet(String, SigningKey)} —— 调用方拥有 SigningKey 生命周期。
 *       {@link #getKeyHolder()} 返回 {@link Optional#empty()}——远程密钥没有可导出的字节。</li>
 * </ol>
 */
public class TronWallet implements Wallet {

    private final String id;
    private final Address address;
    private final KeyHolder keyHolder;        // null = 远程钱包
    private final SigningKey ownedSigningKey; // 本地场景由本对象创建并负责销毁；远程场景为 null
    private final TronSigner signer;
    private volatile boolean destroyed = false;

    /** 本地钱包：从 32 字节私钥构造。 */
    public TronWallet(String id, byte[] privateKey, boolean exportable) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        byte[] pkCopy = SecureBytes.copy(privateKey);
        try {
            this.keyHolder = new TronKeyHolder(pkCopy, exportable);
            this.ownedSigningKey = new Secp256k1Signer(pkCopy);
            this.signer = new TronSigner(ownedSigningKey);
            this.address = keyHolder.getAddress();
            this.id = id != null ? id : address.toString();
        } finally {
            SecureBytes.secureWipe(pkCopy);
        }
    }

    /**
     * 远程钱包：用外部托管的 {@link SigningKey}（KMS、HSM、硬件钱包等）。
     * SigningKey 的生命周期由调用方负责。
     */
    public TronWallet(String id, SigningKey signingKey) {
        if (signingKey == null) {
            throw new IllegalArgumentException("signingKey must not be null");
        }
        this.keyHolder = null;
        this.ownedSigningKey = null;
        this.signer = new TronSigner(signingKey);
        this.address = TronAddress.fromPublicKey(signingKey.getPublicKey());
        this.id = id != null ? id : address.toString();
    }

    /** 子类扩展用：调用方负责保证 keyHolder 与 signer 的密钥一致性。 */
    protected TronWallet(String id, TronKeyHolder keyHolder, TronSigner signer) {
        if (keyHolder == null || signer == null) {
            throw new IllegalArgumentException("keyHolder and signer must not be null");
        }
        this.keyHolder = keyHolder;
        this.ownedSigningKey = null;
        this.signer = signer;
        this.address = keyHolder.getAddress();
        this.id = id != null ? id : address.toString();
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public Address getAddress() {
        return address;
    }

    @Override
    public Optional<KeyHolder> getKeyHolder() {
        return Optional.ofNullable(keyHolder);
    }

    @Override
    public Signer getSigner() {
        return signer;
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            signer.destroy();
            if (keyHolder != null) keyHolder.destroy();
            if (ownedSigningKey != null) ownedSigningKey.destroy();
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed
                || signer.isDestroyed()
                || (keyHolder != null && keyHolder.isDestroyed());
    }

    @Override
    public String toString() {
        return "TronWallet{address=" + address + "}";
    }
}
