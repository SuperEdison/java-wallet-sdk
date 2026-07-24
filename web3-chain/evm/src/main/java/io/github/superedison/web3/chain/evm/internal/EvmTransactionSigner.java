package io.github.superedison.web3.chain.evm.internal;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.evm.tx.EvmRawTransaction;
import io.github.superedison.web3.chain.evm.tx.EvmSignedTransaction;
import io.github.superedison.web3.chain.spi.TransactionSigner;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SignatureScheme;
import io.github.superedison.web3.core.signer.SigningKey;

/**
 * EVM 交易签名器，封装 encode -> hash -> sign -> assemble。
 */
public final class EvmTransactionSigner implements TransactionSigner<EvmRawTransaction, EvmSignedTransaction> {

    private final EvmTransactionEncoder encoder;
    private final EvmTransactionHasher hasher;

    public EvmTransactionSigner(EvmTransactionEncoder encoder, EvmTransactionHasher hasher) {
        this.encoder = encoder;
        this.hasher = hasher;
    }

    @Override
    public EvmSignedTransaction sign(EvmRawTransaction tx, SigningKey key) {
        if (key.getScheme() != SignatureScheme.ECDSA_SECP256K1) {
            throw new IllegalArgumentException("EVM requires secp256k1 signing key");
        }

        byte[] encodedForSigning = encoder.encode(tx);
        byte[] hash = hasher.hash(encodedForSigning);

        Signature sig = key.sign(hash);
        EvmSignature evmSig = EvmSignature.fromSignerCompact(sig.bytes()).toEip155(tx.getChainId());
        byte[] signedBytes = encoder.encodeSigned(tx, evmSig);
        byte[] txHash = hasher.hash(signedBytes);

        String from = EvmAddress.fromPublicKey(key.getPublicKey()).toChecksumHex();

        return new EvmSignedTransaction(tx, evmSig, from, signedBytes, txHash);
    }
}
