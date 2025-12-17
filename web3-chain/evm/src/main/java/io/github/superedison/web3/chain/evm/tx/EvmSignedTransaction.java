package io.github.superedison.web3.chain.evm.tx;

import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.core.tx.SignedTransaction;

import java.util.Arrays;

/**
 * EVM 已签名交易。只保存结果，不做再次签名或编码。
 */
public final class EvmSignedTransaction implements SignedTransaction<EvmRawTransaction> {

    private final EvmRawTransaction rawTransaction;
    private final EvmSignature signature;
    private final String from;
    private final byte[] rawBytes;
    private final byte[] txHash;

    public EvmSignedTransaction(
            EvmRawTransaction rawTransaction,
            EvmSignature signature,
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
    public EvmRawTransaction rawTransaction() {
        return rawTransaction;
    }

    public EvmSignature signature() {
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

    // Convenience helpers for existing call sites
    public String txHashHex() {
        return "0x" + bytesToHex(txHash);
    }

    public String encodeHex() {
        return "0x" + bytesToHex(rawBytes);
    }

    public boolean isValid() {
        return rawTransaction != null && signature != null && from != null && rawBytes.length > 0 && txHash.length > 0;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
