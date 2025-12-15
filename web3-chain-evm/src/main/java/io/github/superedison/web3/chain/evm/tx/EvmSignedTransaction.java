package io.github.superedison.web3.chain.evm.tx;

import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.chain.evm.rlp.RlpEncoder;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.SignedTransaction;
import io.github.superedison.web3.crypto.hash.Keccak256;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * EVM 已签名交易
 */
public final class EvmSignedTransaction implements SignedTransaction {

    private final EvmRawTransaction rawTransaction;
    private final EvmSignature signature;
    private final String from;
    private byte[] encoded;
    private byte[] txHash;

    public EvmSignedTransaction(EvmRawTransaction rawTransaction, EvmSignature signature, String from) {
        this.rawTransaction = rawTransaction;
        this.signature = signature;
        this.from = from;
    }

    @Override
    public RawTransaction getRawTransaction() {
        return rawTransaction;
    }

    @Override
    public Signature getSignature() {
        return signature;
    }

    @Override
    public String getFrom() {
        return from;
    }

    @Override
    public byte[] getTransactionHash() {
        if (txHash == null) {
            txHash = Keccak256.hash(encode());
        }
        return Arrays.copyOf(txHash, txHash.length);
    }

    /**
     * 获取交易哈希的十六进制字符串
     */
    public String getTransactionHashHex() {
        return "0x" + bytesToHex(getTransactionHash());
    }

    @Override
    public byte[] encode() {
        if (encoded == null) {
            encoded = encodeSignedTransaction();
        }
        return Arrays.copyOf(encoded, encoded.length);
    }

    /**
     * 获取十六进制编码（用于广播）
     */
    public String encodeHex() {
        return "0x" + bytesToHex(encode());
    }

    @Override
    public boolean isValid() {
        return signature != null && from != null && !from.isEmpty();
    }

    /**
     * RLP 编码已签名交易
     * RLP([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
     */
    private byte[] encodeSignedTransaction() {
        List<byte[]> fields = new ArrayList<>();
        fields.add(RlpEncoder.encodeBigInteger(rawTransaction.getNonce()));
        fields.add(RlpEncoder.encodeBigInteger(rawTransaction.getGasPrice()));
        fields.add(RlpEncoder.encodeBigInteger(rawTransaction.getGasLimit()));
        fields.add(RlpEncoder.encodeAddress(rawTransaction.getTo()));
        fields.add(RlpEncoder.encodeBigInteger(rawTransaction.getValue()));
        fields.add(RlpEncoder.encodeBytes(rawTransaction.getData()));

        // v, r, s
        fields.add(RlpEncoder.encodeLong(signature.getV()));
        fields.add(RlpEncoder.encodeBigInteger(signature.getRBigInt()));
        fields.add(RlpEncoder.encodeBigInteger(signature.getSBigInt()));

        return RlpEncoder.encodeList(fields);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}