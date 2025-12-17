package io.github.superedison.web3.chain.tron.tx;

import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.core.tx.SignedTransaction;

import java.util.Arrays;

/**
 * TRON signed transaction. Holds result only (no re-encode/sign).
 */
public final class TronSignedTransaction implements SignedTransaction<TronRawTransaction> {

    private final TronRawTransaction rawTransaction;
    private final TronSignature signature;
    private final String from;
    // broadcast bytes + txid
    private final byte[] rawBytes;
    private final byte[] txHash;   // txid = SHA256(raw_data)

    public TronSignedTransaction(
            TronRawTransaction rawTransaction,
            TronSignature signature,
            String from,
            byte[] rawBytes,
            byte[] txHash
    ) {
        this.rawTransaction = rawTransaction;
        this.signature = signature;
        this.from = from;
        this.rawBytes = Arrays.copyOf(rawBytes, rawBytes.length);
        this.txHash = Arrays.copyOf(txHash, txHash.length);
    }

    @Override
    public TronRawTransaction rawTransaction() {
        return rawTransaction;
    }

    public TronSignature signature() {
        return signature;
    }

    @Override
    public byte[] rawBytes() {
        return Arrays.copyOf(rawBytes, rawBytes.length);
    }

    @Override
    public byte[] txHash() {
        return Arrays.copyOf(txHash, txHash.length);
    }

    @Override
    public String from() {
        return from;
    }

    public String txHashHex() {
        return bytesToHex(txHash);
    }

    public String encodeHex() {
        return bytesToHex(rawBytes);
    }

    public boolean isValid() {
        return rawTransaction != null && signature != null && rawBytes.length > 0 && txHash.length > 0;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
