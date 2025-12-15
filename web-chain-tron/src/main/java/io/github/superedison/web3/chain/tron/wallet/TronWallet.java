package io.github.superedison.web3.chain.tron.wallet;

import io.github.superedison.web3.core.signer.Signer;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.KeyHolder;
import io.github.superedison.web3.core.wallet.Wallet;
import io.github.superedison.web3.crypto.util.SecureBytes;

/**
 * 基础 TRON 钱包实现。
 */
public class TronWallet implements Wallet {

    private final String id;
    private final Address address;
    private final TronKeyHolder keyHolder;
    private final TronSigner signer;
    private volatile boolean destroyed = false;

    public TronWallet(String id, byte[] privateKey, boolean exportable) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        byte[] pkCopy = SecureBytes.copy(privateKey);
        this.keyHolder = new TronKeyHolder(pkCopy, exportable);
        this.signer = new TronSigner(pkCopy);
        SecureBytes.secureWipe(pkCopy);
        this.address = keyHolder.getAddress();
        this.id = id != null ? id : address.toString();
    }

    protected TronWallet(String id, TronKeyHolder keyHolder, TronSigner signer) {
        this.id = id != null ? id : keyHolder.getAddress().toString();
        this.address = keyHolder.getAddress();
        this.keyHolder = keyHolder;
        this.signer = signer;
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
    public KeyHolder getKeyHolder() {
        return keyHolder;
    }

    @Override
    public Signer getSigner() {
        return signer;
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            signer.destroy();
            keyHolder.destroy();
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed || signer.isDestroyed() || keyHolder.isDestroyed();
    }

    @Override
    public String toString() {
        return "TronWallet{***REDACTED***}";
    }
}
