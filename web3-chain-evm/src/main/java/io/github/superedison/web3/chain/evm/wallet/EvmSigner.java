package io.github.superedison.web3.chain.evm.wallet;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.Signer;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

/**
 * EVM 签名器，实现 Signer 接口。
 */
public final class EvmSigner implements Signer {

    private final EvmAddress address;
    private final Secp256k1Signer signingKey;
    private volatile boolean destroyed = false;

    public EvmSigner(byte[] privateKey) {
        this.signingKey = new Secp256k1Signer(privateKey);
        this.address = EvmAddress.fromPublicKey(signingKey.getPublicKey());
    }

    @Override
    public SignatureScheme getScheme() {
        return SignatureScheme.ECDSA_SECP256K1;
    }

    @Override
    public EvmAddress getAddress() {
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
        return "EvmSigner{***REDACTED***}";
    }
}
