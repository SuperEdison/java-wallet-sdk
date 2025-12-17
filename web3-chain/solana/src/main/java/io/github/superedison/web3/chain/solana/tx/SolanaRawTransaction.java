package io.github.superedison.web3.chain.solana.tx;

import io.github.superedison.web3.core.tx.RawTransaction;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Solana 原始交易
 *
 * Solana 交易由以下部分组成：
 * 1. 签名数组
 * 2. 消息头（签名数量、只读账户数量等）
 * 3. 账户地址数组
 * 4. 最近的区块哈希
 * 5. 指令数组
 */
public final class SolanaRawTransaction implements RawTransaction {

    private final byte[] recentBlockhash;
    private final List<AccountMeta> accounts;
    private final List<Instruction> instructions;
    private final byte[] feePayer;

    private SolanaRawTransaction(Builder builder) {
        this.recentBlockhash = builder.recentBlockhash;
        this.accounts = Collections.unmodifiableList(new ArrayList<>(builder.accounts));
        this.instructions = Collections.unmodifiableList(new ArrayList<>(builder.instructions));
        this.feePayer = builder.feePayer;
    }

    public static Builder builder() {
        return new Builder();
    }

    public byte[] getRecentBlockhash() {
        return Arrays.copyOf(recentBlockhash, recentBlockhash.length);
    }

    public List<AccountMeta> getAccounts() {
        return accounts;
    }

    public List<Instruction> getInstructions() {
        return instructions;
    }

    public byte[] getFeePayer() {
        return feePayer != null ? Arrays.copyOf(feePayer, feePayer.length) : null;
    }

    /**
     * 账户元数据
     */
    public record AccountMeta(
            byte[] pubkey,
            boolean isSigner,
            boolean isWritable
    ) {
        public AccountMeta {
            pubkey = Arrays.copyOf(pubkey, pubkey.length);
        }

        public byte[] pubkey() {
            return Arrays.copyOf(pubkey, pubkey.length);
        }
    }

    /**
     * 交易指令
     */
    public record Instruction(
            byte[] programId,
            List<Integer> accountIndices,
            byte[] data
    ) {
        public Instruction {
            programId = Arrays.copyOf(programId, programId.length);
            accountIndices = Collections.unmodifiableList(new ArrayList<>(accountIndices));
            data = data != null ? Arrays.copyOf(data, data.length) : new byte[0];
        }

        public byte[] programId() {
            return Arrays.copyOf(programId, programId.length);
        }

        public byte[] data() {
            return Arrays.copyOf(data, data.length);
        }
    }

    public static class Builder {
        private byte[] recentBlockhash;
        private final List<AccountMeta> accounts = new ArrayList<>();
        private final List<Instruction> instructions = new ArrayList<>();
        private byte[] feePayer;

        public Builder recentBlockhash(byte[] recentBlockhash) {
            if (recentBlockhash == null || recentBlockhash.length != 32) {
                throw new IllegalArgumentException("Recent blockhash must be 32 bytes");
            }
            this.recentBlockhash = Arrays.copyOf(recentBlockhash, recentBlockhash.length);
            return this;
        }

        public Builder recentBlockhash(String base58Blockhash) {
            byte[] decoded = io.github.superedison.web3.chain.solana.address.Base58.decode(base58Blockhash);
            return recentBlockhash(decoded);
        }

        public Builder feePayer(byte[] feePayer) {
            if (feePayer == null || feePayer.length != 32) {
                throw new IllegalArgumentException("Fee payer must be 32 bytes");
            }
            this.feePayer = Arrays.copyOf(feePayer, feePayer.length);
            return this;
        }

        public Builder addAccount(byte[] pubkey, boolean isSigner, boolean isWritable) {
            accounts.add(new AccountMeta(pubkey, isSigner, isWritable));
            return this;
        }

        public Builder addInstruction(byte[] programId, List<Integer> accountIndices, byte[] data) {
            instructions.add(new Instruction(programId, accountIndices, data));
            return this;
        }

        public SolanaRawTransaction build() {
            if (recentBlockhash == null) {
                throw new IllegalStateException("Recent blockhash is required");
            }
            if (feePayer == null && !accounts.isEmpty()) {
                // 默认使用第一个签名者作为费用支付者
                for (AccountMeta account : accounts) {
                    if (account.isSigner()) {
                        feePayer = account.pubkey();
                        break;
                    }
                }
            }
            return new SolanaRawTransaction(this);
        }
    }
}