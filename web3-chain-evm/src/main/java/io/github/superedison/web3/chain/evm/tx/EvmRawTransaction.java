package io.github.superedison.web3.chain.evm.tx;

import io.github.superedison.web3.chain.evm.rlp.RlpEncoder;
import io.github.superedison.web3.core.transaction.RawTransaction;
import io.github.superedison.web3.core.transaction.TransactionType;
import io.github.superedison.web3.crypto.hash.Keccak256;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * EVM Legacy 交易
 * 支持 EIP-155
 */
public final class EvmRawTransaction implements RawTransaction {

    private final BigInteger nonce;
    private final BigInteger gasPrice;
    private final BigInteger gasLimit;
    private final byte[] to;          // null 表示合约创建
    private final BigInteger value;
    private final byte[] data;
    private final long chainId;

    private EvmRawTransaction(Builder builder) {
        this.nonce = builder.nonce;
        this.gasPrice = builder.gasPrice;
        this.gasLimit = builder.gasLimit;
        this.to = builder.to;
        this.value = builder.value;
        this.data = builder.data;
        this.chainId = builder.chainId;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public TransactionType getType() {
        return TransactionType.EVM_LEGACY;
    }

    @Override
    public byte[] encode() {
        return encodeForSigning();
    }

    @Override
    public byte[] hash() {
        return Keccak256.hash(encodeForSigning());
    }

    /**
     * EIP-155 签名编码
     * RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])
     */
    public byte[] encodeForSigning() {
        List<byte[]> fields = new ArrayList<>();
        fields.add(RlpEncoder.encodeBigInteger(nonce));
        fields.add(RlpEncoder.encodeBigInteger(gasPrice));
        fields.add(RlpEncoder.encodeBigInteger(gasLimit));
        fields.add(RlpEncoder.encodeAddress(to));
        fields.add(RlpEncoder.encodeBigInteger(value));
        fields.add(RlpEncoder.encodeBytes(data != null ? data : new byte[0]));

        if (chainId > 0) {
            // EIP-155
            fields.add(RlpEncoder.encodeLong(chainId));
            fields.add(RlpEncoder.encodeBigInteger(BigInteger.ZERO));
            fields.add(RlpEncoder.encodeBigInteger(BigInteger.ZERO));
        }

        return RlpEncoder.encodeList(fields);
    }

    // Getters
    public BigInteger getNonce() { return nonce; }
    public BigInteger getGasPrice() { return gasPrice; }
    public BigInteger getGasLimit() { return gasLimit; }
    public byte[] getTo() { return to != null ? Arrays.copyOf(to, to.length) : null; }
    public BigInteger getValue() { return value; }
    public byte[] getData() { return data != null ? Arrays.copyOf(data, data.length) : new byte[0]; }
    public long getChainId() { return chainId; }
    public boolean isContractCreation() { return to == null || to.length == 0; }

    public static class Builder {
        private BigInteger nonce = BigInteger.ZERO;
        private BigInteger gasPrice = BigInteger.ZERO;
        private BigInteger gasLimit = BigInteger.valueOf(21000);
        private byte[] to;
        private BigInteger value = BigInteger.ZERO;
        private byte[] data;
        private long chainId = 1;

        public Builder nonce(BigInteger nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder nonce(long nonce) {
            this.nonce = BigInteger.valueOf(nonce);
            return this;
        }

        public Builder gasPrice(BigInteger gasPrice) {
            this.gasPrice = gasPrice;
            return this;
        }

        public Builder gasLimit(BigInteger gasLimit) {
            this.gasLimit = gasLimit;
            return this;
        }

        public Builder gasLimit(long gasLimit) {
            this.gasLimit = BigInteger.valueOf(gasLimit);
            return this;
        }

        public Builder to(byte[] to) {
            this.to = to;
            return this;
        }

        public Builder to(String toHex) {
            if (toHex == null || toHex.isEmpty()) {
                this.to = null;
            } else {
                String hex = toHex.startsWith("0x") ? toHex.substring(2) : toHex;
                this.to = hexToBytes(hex);
            }
            return this;
        }

        public Builder value(BigInteger value) {
            this.value = value;
            return this;
        }

        public Builder data(byte[] data) {
            this.data = data;
            return this;
        }

        public Builder data(String dataHex) {
            if (dataHex == null || dataHex.isEmpty()) {
                this.data = new byte[0];
            } else {
                String hex = dataHex.startsWith("0x") ? dataHex.substring(2) : dataHex;
                this.data = hexToBytes(hex);
            }
            return this;
        }

        public Builder chainId(long chainId) {
            this.chainId = chainId;
            return this;
        }

        public EvmRawTransaction build() {
            return new EvmRawTransaction(this);
        }

        private static byte[] hexToBytes(String hex) {
            byte[] bytes = new byte[hex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return bytes;
        }
    }
}