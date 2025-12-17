package io.github.superedison.web3.chain.solana.internal;

import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction;
import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction.AccountMeta;
import io.github.superedison.web3.chain.solana.tx.SolanaRawTransaction.Instruction;
import io.github.superedison.web3.chain.spi.TransactionEncoder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

/**
 * Solana 交易编码器
 *
 * Solana 交易消息格式：
 * 1. 紧凑数组长度（签名数量）
 * 2. 签名数组（签名后添加）
 * 3. 消息：
 *    - 消息头（3 字节）
 *    - 账户地址数组
 *    - 最近区块哈希（32 字节）
 *    - 指令数组
 */
public final class SolanaTransactionEncoder implements TransactionEncoder<SolanaRawTransaction> {

    @Override
    public byte[] encode(SolanaRawTransaction tx) {
        return encodeMessage(tx);
    }

    /**
     * 编码交易消息（用于签名）
     */
    public byte[] encodeMessage(SolanaRawTransaction tx) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // 收集所有唯一账户，按顺序排列
            List<AccountMeta> sortedAccounts = collectAndSortAccounts(tx);

            // 构建账户索引映射
            Map<String, Integer> accountIndexMap = new HashMap<>();
            for (int i = 0; i < sortedAccounts.size(); i++) {
                accountIndexMap.put(bytesToHex(sortedAccounts.get(i).pubkey()), i);
            }

            // 计算消息头
            int numRequiredSignatures = 0;
            int numReadonlySignedAccounts = 0;
            int numReadonlyUnsignedAccounts = 0;

            for (AccountMeta account : sortedAccounts) {
                if (account.isSigner()) {
                    numRequiredSignatures++;
                    if (!account.isWritable()) {
                        numReadonlySignedAccounts++;
                    }
                } else if (!account.isWritable()) {
                    numReadonlyUnsignedAccounts++;
                }
            }

            // 写入消息头（3 字节）
            baos.write(numRequiredSignatures);
            baos.write(numReadonlySignedAccounts);
            baos.write(numReadonlyUnsignedAccounts);

            // 写入账户地址数组
            writeCompactArrayLength(baos, sortedAccounts.size());
            for (AccountMeta account : sortedAccounts) {
                baos.write(account.pubkey());
            }

            // 写入最近区块哈希（32 字节）
            baos.write(tx.getRecentBlockhash());

            // 写入指令数组
            List<Instruction> instructions = tx.getInstructions();
            writeCompactArrayLength(baos, instructions.size());

            for (Instruction instruction : instructions) {
                // 写入程序 ID 索引
                String programIdHex = bytesToHex(instruction.programId());
                Integer programIdIndex = accountIndexMap.get(programIdHex);
                if (programIdIndex == null) {
                    throw new IllegalStateException("Program ID not found in accounts: " + programIdHex);
                }
                baos.write(programIdIndex);

                // 写入账户索引数组
                List<Integer> accountIndices = instruction.accountIndices();
                writeCompactArrayLength(baos, accountIndices.size());
                for (Integer idx : accountIndices) {
                    baos.write(idx);
                }

                // 写入指令数据
                byte[] data = instruction.data();
                writeCompactArrayLength(baos, data.length);
                baos.write(data);
            }

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode Solana transaction", e);
        }
    }

    /**
     * 编码已签名交易（用于广播）
     */
    public byte[] encodeSigned(SolanaRawTransaction tx, byte[][] signatures) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // 写入签名数组
            writeCompactArrayLength(baos, signatures.length);
            for (byte[] signature : signatures) {
                baos.write(signature);
            }

            // 写入消息
            baos.write(encodeMessage(tx));

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode signed Solana transaction", e);
        }
    }

    /**
     * 收集并排序账户
     * 排序规则：
     * 1. 可签名可写账户（费用支付者优先）
     * 2. 可签名只读账户
     * 3. 不可签名可写账户
     * 4. 不可签名只读账户
     */
    private List<AccountMeta> collectAndSortAccounts(SolanaRawTransaction tx) {
        Set<String> seen = new HashSet<>();
        List<AccountMeta> result = new ArrayList<>();

        // 首先添加费用支付者
        byte[] feePayer = tx.getFeePayer();
        if (feePayer != null) {
            result.add(new AccountMeta(feePayer, true, true));
            seen.add(bytesToHex(feePayer));
        }

        // 添加交易中的账户
        for (AccountMeta account : tx.getAccounts()) {
            String key = bytesToHex(account.pubkey());
            if (!seen.contains(key)) {
                result.add(account);
                seen.add(key);
            }
        }

        // 从指令中添加程序 ID
        for (Instruction instruction : tx.getInstructions()) {
            String key = bytesToHex(instruction.programId());
            if (!seen.contains(key)) {
                result.add(new AccountMeta(instruction.programId(), false, false));
                seen.add(key);
            }
        }

        // 按照 Solana 的规则排序
        result.sort((a, b) -> {
            // 签名者优先
            if (a.isSigner() != b.isSigner()) {
                return a.isSigner() ? -1 : 1;
            }
            // 在同一类别中，可写优先
            if (a.isWritable() != b.isWritable()) {
                return a.isWritable() ? -1 : 1;
            }
            return 0;
        });

        return result;
    }

    /**
     * 写入紧凑数组长度（变长编码）
     */
    private void writeCompactArrayLength(ByteArrayOutputStream baos, int length) {
        while (true) {
            int elem = length & 0x7f;
            length >>= 7;
            if (length == 0) {
                baos.write(elem);
                break;
            } else {
                baos.write(elem | 0x80);
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
