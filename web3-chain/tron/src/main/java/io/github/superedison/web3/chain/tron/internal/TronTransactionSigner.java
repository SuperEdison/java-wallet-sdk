package io.github.superedison.web3.chain.tron.internal;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.chain.tron.protobuf.TronProtobuf;
import io.github.superedison.web3.chain.tron.tx.TronRawTransaction;
import io.github.superedison.web3.chain.tron.tx.TronSignedTransaction;
import io.github.superedison.web3.chain.spi.TransactionSigner;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;

/**
 * TRON 交易签名器：encode raw_data -> hash -> sign -> assemble。
 */
public final class TronTransactionSigner implements TransactionSigner<TronRawTransaction, TronSignedTransaction> {

    private final TronTransactionEncoder encoder;
    private final TronTransactionHasher hasher;

    public TronTransactionSigner(TronTransactionEncoder encoder, TronTransactionHasher hasher) {
        this.encoder = encoder;
        this.hasher = hasher;
    }

    @Override
    public TronSignedTransaction sign(TronRawTransaction tx, SigningKey key) {
        if (key.getScheme() != SignatureScheme.ECDSA_SECP256K1) {
            throw new IllegalArgumentException("TRON requires secp256k1 signing key");
        }

        byte[] rawData = encoder.encode(tx);
        byte[] txHash = hasher.hash(rawData);

        Signature sig = key.sign(txHash);
        byte[] sigBytes = sig.bytes();
        if (sigBytes.length != 65) {
            throw new IllegalArgumentException("Signature must be 65 bytes for TRON");
        }

        TronSignature tronSig = TronSignature.fromCompact(sigBytes);
        byte[] signedBytes = TronProtobuf.encodeSignedTransaction(rawData, tronSig.bytes());

        String from = TronAddress.fromPublicKey(key.getPublicKey()).toBase58();

        return new TronSignedTransaction(tx, tronSig, from, signedBytes, txHash);
    }
}
