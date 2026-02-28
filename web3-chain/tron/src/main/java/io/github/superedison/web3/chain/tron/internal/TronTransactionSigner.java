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
        if (!(sig instanceof io.github.superedison.web3.crypto.ecc.Secp256k1Signer.Secp256k1Signature secp256k1Sig)) {
            throw new IllegalArgumentException("TRON requires Secp256k1Signature");
        }

        TronSignature tronSig = TronSignature.fromSecp256k1Signature(secp256k1Sig);
        byte[] signedBytes = TronProtobuf.encodeSignedTransaction(rawData, tronSig.bytes());

        String from = TronAddress.fromPublicKey(key.getPublicKey()).toBase58();

        return new TronSignedTransaction(tx, tronSig, from, signedBytes, txHash);
    }
}
