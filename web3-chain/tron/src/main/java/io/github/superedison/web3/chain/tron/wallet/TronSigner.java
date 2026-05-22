package io.github.superedison.web3.chain.tron.wallet;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.Signer;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;

/**
 * TRON 签名器，实现 {@link Signer}。
 *
 * 非拥有式：构造时收一个 {@link SigningKey}，**不接管其生命周期**。
 * destroy() 只标记本对象，不会传递到底层——这样允许多个 Signer 共享同一个 KMS Key。
 *
 * 本地用：{@code new TronSigner(new Secp256k1Signer(privateKey))}
 * KMS 用：{@code new TronSigner(awsKmsSecp256k1Key)}
 */
public final class TronSigner implements Signer {

    private final TronAddress address;
    private final SigningKey signingKey;
    private volatile boolean destroyed = false;

    public TronSigner(SigningKey signingKey) {
        if (signingKey == null) {
            throw new IllegalArgumentException("signingKey must not be null");
        }
        if (signingKey.getScheme() != SignatureScheme.ECDSA_SECP256K1) {
            throw new IllegalArgumentException(
                    "TronSigner requires ECDSA_SECP256K1, got " + signingKey.getScheme());
        }
        this.signingKey = signingKey;
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
        destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed || signingKey.isDestroyed();
    }

    private void checkNotDestroyed() {
        if (isDestroyed()) {
            throw new IllegalStateException("Signer has been destroyed");
        }
    }

    @Override
    public String toString() {
        return "TronSigner{address=" + address + "}";
    }
}
