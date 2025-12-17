package io.github.superedison.web3.chain.tron.wallet;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.core.wallet.Address;
import io.github.superedison.web3.core.wallet.KeyHolder;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.util.SecureBytes;

/**
 * TRON KeyHolder 实现，封装私钥与地址。
 * 默认不在 toString 中暴露密钥，支持可选导出。
 */
public final class TronKeyHolder implements KeyHolder {

    private final byte[] privateKey;
    private final byte[] publicKey;
    private final TronAddress address;
    private final boolean exportable;
    private volatile boolean destroyed = false;

    public TronKeyHolder(byte[] privateKey, boolean exportable) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        this.privateKey = SecureBytes.copy(privateKey);
        this.publicKey = Secp256k1Signer.derivePublicKey(this.privateKey, false);
        this.address = TronAddress.fromPublicKey(this.publicKey);
        this.exportable = exportable;
    }

    @Override
    public byte[] getPublicKey() {
        checkNotDestroyed();
        return SecureBytes.copy(publicKey);
    }

    @Override
    public Address getAddress() {
        return address;
    }

    @Override
    public boolean canExportPrivateKey() {
        return exportable && !destroyed;
    }

    @Override
    public byte[] exportPrivateKey() {
        checkNotDestroyed();
        if (!exportable) {
            throw new UnsupportedOperationException("Private key export is disabled");
        }
        return SecureBytes.copy(privateKey);
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            SecureBytes.secureWipe(privateKey);
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("KeyHolder has been destroyed");
        }
    }

    @Override
    public String toString() {
        return "TronKeyHolder{***REDACTED***}";
    }
}
