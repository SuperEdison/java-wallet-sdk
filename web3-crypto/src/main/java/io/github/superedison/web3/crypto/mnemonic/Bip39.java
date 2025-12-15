package io.github.superedison.web3.crypto.mnemonic;

import io.github.superedison.web3.crypto.hash.Sha256;
import io.github.superedison.web3.crypto.util.SecureBytes;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * BIP-39 助记词实现
 * 支持生成、验证助记词和派生种子
 */
public final class Bip39 {

    private static final int PBKDF2_ITERATIONS = 2048;
    private static final int SEED_LENGTH = 64;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private Bip39() {}

    /**
     * 生成助记词
     * @param wordCount 助记词数量 (12, 15, 18, 21, 24)
     * @return 助记词列表
     */
    public static List<String> generateMnemonic(int wordCount) {
        int entropyBits = wordCountToEntropyBits(wordCount);
        byte[] entropy = new byte[entropyBits / 8];
        SECURE_RANDOM.nextBytes(entropy);
        return entropyToMnemonic(entropy);
    }

    /**
     * 生成12词助记词
     */
    public static List<String> generateMnemonic() {
        return generateMnemonic(12);
    }

    /**
     * 从熵生成助记词
     * @param entropy 熵字节数组 (16, 20, 24, 28, 32 字节)
     * @return 助记词列表
     */
    public static List<String> entropyToMnemonic(byte[] entropy) {
        int entropyBits = entropy.length * 8;
        int checksumBits = entropyBits / 32;
        int totalBits = entropyBits + checksumBits;
        int wordCount = totalBits / 11;

        // 计算校验和
        byte[] hash = Sha256.hash(entropy);

        // 合并熵和校验和
        byte[] entropyWithChecksum = new byte[entropy.length + 1];
        System.arraycopy(entropy, 0, entropyWithChecksum, 0, entropy.length);
        entropyWithChecksum[entropy.length] = hash[0];

        // 转换为11位索引
        List<String> words = new ArrayList<>(wordCount);
        String[] wordList = Bip39WordList.ENGLISH;

        for (int i = 0; i < wordCount; i++) {
            int index = extractBits(entropyWithChecksum, i * 11, 11);
            words.add(wordList[index]);
        }

        return words;
    }

    /**
     * 从助记词恢复熵
     * @param mnemonic 助记词列表
     * @return 熵字节数组
     */
    public static byte[] mnemonicToEntropy(List<String> mnemonic) {
        if (!validateMnemonic(mnemonic)) {
            throw new IllegalArgumentException("Invalid mnemonic");
        }

        String[] wordList = Bip39WordList.ENGLISH;
        int wordCount = mnemonic.size();
        int totalBits = wordCount * 11;
        int checksumBits = wordCount / 3;
        int entropyBits = totalBits - checksumBits;

        // 将单词转换为索引并组合成位
        byte[] bits = new byte[(totalBits + 7) / 8];

        for (int i = 0; i < wordCount; i++) {
            int index = findWordIndex(mnemonic.get(i), wordList);
            setBits(bits, i * 11, 11, index);
        }

        // 提取熵
        byte[] entropy = new byte[entropyBits / 8];
        System.arraycopy(bits, 0, entropy, 0, entropy.length);

        return entropy;
    }

    /**
     * 从助记词派生种子
     * @param mnemonic 助记词列表
     * @param passphrase 密码（可选）
     * @return 64字节种子
     */
    public static byte[] mnemonicToSeed(List<String> mnemonic, String passphrase) {
        String mnemonicStr = String.join(" ", mnemonic);
        return mnemonicToSeed(mnemonicStr, passphrase);
    }

    /**
     * 从助记词字符串派生种子
     * @param mnemonic 助记词字符串（空格分隔）
     * @param passphrase 密码（可选）
     * @return 64字节种子
     */
    public static byte[] mnemonicToSeed(String mnemonic, String passphrase) {
        // NFKD 标准化
        String normalizedMnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD);
        String normalizedPassphrase = Normalizer.normalize(
                "mnemonic" + (passphrase != null ? passphrase : ""),
                Normalizer.Form.NFKD
        );

        try {
            PBEKeySpec spec = new PBEKeySpec(
                    normalizedMnemonic.toCharArray(),
                    normalizedPassphrase.getBytes(StandardCharsets.UTF_8),
                    PBKDF2_ITERATIONS,
                    SEED_LENGTH * 8
            );
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive seed", e);
        }
    }

    /**
     * 从助记词派生种子（无密码）
     */
    public static byte[] mnemonicToSeed(List<String> mnemonic) {
        return mnemonicToSeed(mnemonic, "");
    }

    /**
     * 验证助记词
     * @param mnemonic 助记词列表
     * @return 是否有效
     */
    public static boolean validateMnemonic(List<String> mnemonic) {
        if (mnemonic == null || mnemonic.isEmpty()) {
            return false;
        }

        int wordCount = mnemonic.size();
        if (wordCount != 12 && wordCount != 15 && wordCount != 18 &&
            wordCount != 21 && wordCount != 24) {
            return false;
        }

        String[] wordList = Bip39WordList.ENGLISH;

        // 检查所有单词是否在词表中
        for (String word : mnemonic) {
            if (findWordIndex(word.toLowerCase(), wordList) == -1) {
                return false;
            }
        }

        // 验证校验和
        try {
            int totalBits = wordCount * 11;
            int checksumBits = wordCount / 3;
            int entropyBits = totalBits - checksumBits;

            byte[] bits = new byte[(totalBits + 7) / 8];
            for (int i = 0; i < wordCount; i++) {
                int index = findWordIndex(mnemonic.get(i).toLowerCase(), wordList);
                setBits(bits, i * 11, 11, index);
            }

            byte[] entropy = new byte[entropyBits / 8];
            System.arraycopy(bits, 0, entropy, 0, entropy.length);

            byte[] hash = Sha256.hash(entropy);
            int checksumFromHash = (hash[0] & 0xFF) >> (8 - checksumBits);
            int checksumFromMnemonic = extractBits(bits, entropyBits, checksumBits);

            return checksumFromHash == checksumFromMnemonic;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 验证助记词字符串
     */
    public static boolean validateMnemonic(String mnemonic) {
        if (mnemonic == null || mnemonic.trim().isEmpty()) {
            return false;
        }
        return validateMnemonic(Arrays.asList(mnemonic.trim().toLowerCase().split("\\s+")));
    }

    private static int wordCountToEntropyBits(int wordCount) {
        return switch (wordCount) {
            case 12 -> 128;
            case 15 -> 160;
            case 18 -> 192;
            case 21 -> 224;
            case 24 -> 256;
            default -> throw new IllegalArgumentException(
                    "Word count must be 12, 15, 18, 21, or 24");
        };
    }

    private static int extractBits(byte[] data, int bitOffset, int numBits) {
        int result = 0;
        for (int i = 0; i < numBits; i++) {
            int byteIndex = (bitOffset + i) / 8;
            int bitIndex = 7 - ((bitOffset + i) % 8);
            if (byteIndex < data.length && ((data[byteIndex] >> bitIndex) & 1) == 1) {
                result |= (1 << (numBits - 1 - i));
            }
        }
        return result;
    }

    private static void setBits(byte[] data, int bitOffset, int numBits, int value) {
        for (int i = 0; i < numBits; i++) {
            int byteIndex = (bitOffset + i) / 8;
            int bitIndex = 7 - ((bitOffset + i) % 8);
            if (((value >> (numBits - 1 - i)) & 1) == 1) {
                data[byteIndex] |= (1 << bitIndex);
            }
        }
    }

    private static int findWordIndex(String word, String[] wordList) {
        // 二分查找
        int low = 0;
        int high = wordList.length - 1;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            int cmp = wordList[mid].compareTo(word);
            if (cmp < 0) {
                low = mid + 1;
            } else if (cmp > 0) {
                high = mid - 1;
            } else {
                return mid;
            }
        }
        return -1;
    }
}