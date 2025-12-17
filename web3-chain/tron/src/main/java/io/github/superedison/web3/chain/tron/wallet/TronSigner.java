package io.github.superedison.web3.chain.tron.wallet;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.Signer;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

/**
 * TRON 签名器，实现 Signer 接口。
 */
public final class TronSigner implements Signer {

    private final TronAddress address;
    private final Secp256k1Signer signingKey;
    private volatile boolean destroyed = false;

    public TronSigner(byte[] privateKey) {
        this.signingKey = new Secp256k1Signer(privateKey);
        this.address = TronAddress.fromPublicKey(signingKey.getPublicKey());
    }

    @Override
    public SignatureScheme getScheme() {
        return SignatureScheme.ECDSA_SECP256K1;
    }

    @Override
    public TronAddress getAddress() {
        return address;
    }

    @Override
    public Signature sign(byte[] hash) {
        checkNotDestroyed();
        return signingKey.sign(hash);
    }

    @Override
    public boolean verify(byte[] hash, Signature signature) {
        checkNotDestroyed();
        if (!(signature instanceof Secp256k1Signer.Secp256k1Signature secp)) {
            return false;
        }
        return Secp256k1Signer.verify(hash, secp.r(), secp.s(), signingKey.getPublicKey());
    }

    @Override
    public void destroy() {
        if (!destroyed) {
            signingKey.destroy();
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed || signingKey.isDestroyed();
    }

    private void checkNotDestroyed() {
        if (destroyed || signingKey.isDestroyed()) {
            throw new IllegalStateException("Signer has been destroyed");
        }
    }

    @Override
    public String toString() {
        return "TronSigner{***REDACTED***}";
    }
}
