package io.github.superedison.web3.chain.tron.tx;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.core.tx.RawTransaction;

import java.util.Arrays;

/**
 * TRON 原始交易（仅承载数据，不做编码/哈希/签名）。
 */
public final class TronRawTransaction implements RawTransaction {

    private final TronTransactionType type;
    private final byte[] ownerAddress;     // 发送者地址 (21字节)
    private final byte[] toAddress;        // 接收者地址 (21字节)
    private final long amount;             // 金额 (sun, 1 TRX = 1_000_000 sun)
    private final byte[] data;             // 合约数据 (可选)
    private final byte[] refBlockBytes;    // 参考区块字节(2字节)
    private final byte[] refBlockHash;     // 参考区块哈希(8字节)
    private final long expiration;         // 过期时间 (毫秒时间戳)
    private final long timestamp;          // 交易时间戳(毫秒)
    private final long feeLimit;           // 费用上限 (用于智能合约)

    private TronRawTransaction(Builder builder) {
        this.type = builder.type;
        this.ownerAddress = builder.ownerAddress;
        this.toAddress = builder.toAddress;
        this.amount = builder.amount;
        this.data = builder.data;
        this.refBlockBytes = builder.refBlockBytes;
        this.refBlockHash = builder.refBlockHash;
        this.expiration = builder.expiration;
        this.timestamp = builder.timestamp;
        this.feeLimit = builder.feeLimit;
    }

    public static Builder builder() {
        return new Builder();
    }

    public TronTransactionType getType() {
        return type;
    }

    public byte[] getOwnerAddress() {
        return ownerAddress != null ? Arrays.copyOf(ownerAddress, ownerAddress.length) : null;
    }

    public byte[] getToAddress() {
        return toAddress != null ? Arrays.copyOf(toAddress, toAddress.length) : null;
    }

    public long getAmount() {
        return amount;
    }

    public byte[] getData() {
        return data != null ? Arrays.copyOf(data, data.length) : null;
    }

    public byte[] getRefBlockBytes() {
        return refBlockBytes != null ? Arrays.copyOf(refBlockBytes, refBlockBytes.length) : null;
    }

    public byte[] getRefBlockHash() {
        return refBlockHash != null ? Arrays.copyOf(refBlockHash, refBlockHash.length) : null;
    }

    public long getExpiration() {
        return expiration;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public long getFeeLimit() {
        return feeLimit;
    }

    public static class Builder {
        private TronTransactionType type = TronTransactionType.TRANSFER_CONTRACT;
        private byte[] ownerAddress;
        private byte[] toAddress;
        private long amount;
        private byte[] data;
        private byte[] refBlockBytes;
        private byte[] refBlockHash;
        private long expiration;
        private long timestamp;
        private long feeLimit;

        public Builder type(TronTransactionType type) {
            this.type = type;
            return this;
        }

        public Builder from(String address) {
            this.ownerAddress = TronAddress.fromBase58(address).toBytes();
            return this;
        }

        public Builder from(byte[] address) {
            this.ownerAddress = Arrays.copyOf(address, address.length);
            return this;
        }

        public Builder to(String address) {
            this.toAddress = TronAddress.fromBase58(address).toBytes();
            return this;
        }

        public Builder to(byte[] address) {
            this.toAddress = Arrays.copyOf(address, address.length);
            return this;
        }

        public Builder amount(long amount) {
            this.amount = amount;
            return this;
        }

        public Builder data(byte[] data) {
            this.data = data != null ? Arrays.copyOf(data, data.length) : null;
            return this;
        }

        public Builder data(String hexData) {
            if (hexData == null || hexData.isEmpty()) {
                this.data = null;
                return this;
            }
            String clean = hexData.startsWith("0x") ? hexData.substring(2) : hexData;
            this.data = hexToBytes(clean);
            return this;
        }

        public Builder refBlockBytes(byte[] bytes) {
            this.refBlockBytes = bytes != null ? Arrays.copyOf(bytes, bytes.length) : null;
            return this;
        }

        public Builder refBlockHash(byte[] hash) {
            this.refBlockHash = hash != null ? Arrays.copyOf(hash, hash.length) : null;
            return this;
        }

        public Builder expiration(long expiration) {
            this.expiration = expiration;
            return this;
        }

        public Builder timestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder feeLimit(long feeLimit) {
            this.feeLimit = feeLimit;
            return this;
        }

        public TronRawTransaction build() {
            if (ownerAddress == null) {
                throw new IllegalArgumentException("Owner address is required");
            }
            if (toAddress == null) {
                throw new IllegalArgumentException("To address is required");
            }
            if (refBlockBytes == null) {
                throw new IllegalArgumentException("refBlockBytes is required");
            }
            if (refBlockHash == null) {
                throw new IllegalArgumentException("refBlockHash is required");
            }
            if (expiration <= 0) {
                throw new IllegalArgumentException("expiration is required");
            }
            if (timestamp <= 0) {
                throw new IllegalArgumentException("timestamp is required");
            }
            return new TronRawTransaction(this);
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
