package io.github.superedison.web3.crypto.kdf;

import io.github.superedison.web3.crypto.hash.Sha256;
import io.github.superedison.web3.crypto.util.SecureBytes;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * BIP-32 分层确定性密钥派生
 */
public final class Bip32 {

    private static final X9ECParameters CURVE = CustomNamedCurves.getByName("secp256k1");
    private static final BigInteger N = CURVE.getN();

    private Bip32() {}

    /**
     * 从种子生成主密钥
     * @param seed 64字节种子
     * @return 扩展密钥 (私钥32字节 + 链码32字节)
     */
    public static ExtendedKey masterKeyFromSeed(byte[] seed) {
        byte[] hmac = hmacSha512("Bitcoin seed".getBytes(StandardCharsets.UTF_8), seed);
        byte[] privateKey = null;
        byte[] chainCode = null;
        try {
            privateKey = Arrays.copyOfRange(hmac, 0, 32);
            chainCode = Arrays.copyOfRange(hmac, 32, 64);

            // 验证私钥有效性
            BigInteger key = new BigInteger(1, privateKey);
            if (key.equals(BigInteger.ZERO) || key.compareTo(N) >= 0) {
                throw new IllegalStateException("Invalid master key derived");
            }

            return new ExtendedKey(privateKey, chainCode, new int[0], 0);
        } finally {
            SecureBytes.secureWipe(hmac);
            SecureBytes.secureWipe(privateKey);
            SecureBytes.secureWipe(chainCode);
        }
    }

    /**
     * 派生子密钥
     * @param parent 父扩展密钥
     * @param index 索引 (0x80000000 以上为硬化派生)
     * @return 子扩展密钥
     */
    public static ExtendedKey deriveChild(ExtendedKey parent, int index) {
        if (parent == null) {
            throw new IllegalArgumentException("Parent key cannot be null");
        }

        synchronized (parent) {
            parent.checkNotDestroyed();

            byte[] data = new byte[37];
            try {
                boolean hardened = (index & 0x80000000) != 0;
                if (hardened) {
                    // 硬化派生: HMAC-SHA512(chainCode, 0x00 || privateKey || index)
                    data[0] = 0x00;
                    System.arraycopy(parent.privateKey, 0, data, 1, 32);
                } else {
                    // 普通派生: HMAC-SHA512(chainCode, publicKey || index)
                    byte[] publicKey = privateKeyToPublicKey(parent.privateKey, true);
                    System.arraycopy(publicKey, 0, data, 0, 33);
                }
                ByteBuffer.wrap(data, 33, 4).putInt(index);

                byte[] hmac = hmacSha512(parent.chainCode, data);
                byte[] il = null;
                byte[] childChainCode = null;
                byte[] childPrivateKey = null;
                byte[] childPrivateKeyBytes = null;
                try {
                    il = Arrays.copyOfRange(hmac, 0, 32);
                    childChainCode = Arrays.copyOfRange(hmac, 32, 64);

                    // 计算子私钥: (il + parentKey) mod n
                    BigInteger ilInt = new BigInteger(1, il);
                    BigInteger parentKeyInt = new BigInteger(1, parent.privateKey);
                    BigInteger childKeyInt = ilInt.add(parentKeyInt).mod(N);

                    if (ilInt.compareTo(N) >= 0 || childKeyInt.equals(BigInteger.ZERO)) {
                        // 防止溢出：确保 index+1 不会跨越 hardened/non-hardened 边界
                        int nextIndex = index + 1;
                        boolean nextHardened = (nextIndex & 0x80000000) != 0;
                        if (hardened != nextHardened) {
                            throw new IllegalStateException("BIP-32 key derivation: index overflow at boundary");
                        }
                        return deriveChild(parent, nextIndex);
                    }

                    childPrivateKeyBytes = childKeyInt.toByteArray();
                    childPrivateKey = SecureBytes.padLeft(childPrivateKeyBytes, 32);

                    int[] newPath = Arrays.copyOf(parent.path, parent.path.length + 1);
                    newPath[newPath.length - 1] = index;

                    return new ExtendedKey(childPrivateKey, childChainCode, newPath, parent.depth + 1);
                } finally {
                    SecureBytes.secureWipe(hmac);
                    SecureBytes.secureWipe(il);
                    SecureBytes.secureWipe(childChainCode);
                    SecureBytes.secureWipe(childPrivateKey);
                    SecureBytes.secureWipe(childPrivateKeyBytes);
                }
            } finally {
                SecureBytes.secureWipe(data);
            }
        }
    }

    /**
     * 按路径派生密钥
     * @param master 主密钥
     * @param path 派生路径，如 "m/44'/60'/0'/0/0"
     * @return 派生的扩展密钥
     */
    public static ExtendedKey derivePath(ExtendedKey master, String path) {
        if (master == null) {
            throw new IllegalArgumentException("Master key cannot be null");
        }
        master.checkNotDestroyed();

        int[] indices = parsePath(path);
        // 根路径不派生子级，但返回独立对象，避免销毁结果时连带销毁 master。
        if (indices.length == 0) {
            return master.copy();
        }

        ExtendedKey current = master;
        try {
            for (int index : indices) {
                ExtendedKey next = deriveChild(current, index);
                if (current != master) {
                    current.destroy();
                }
                current = next;
            }
            return current;
        } catch (RuntimeException | Error e) {
            if (current != master) {
                current.destroy();
            }
            throw e;
        }
    }

    /**
     * 从种子按路径派生密钥
     */
    public static ExtendedKey derivePath(byte[] seed, String path) {
        ExtendedKey master = masterKeyFromSeed(seed);
        try {
            return derivePath(master, path);
        } finally {
            master.destroy();
        }
    }

    /**
     * 私钥转公钥
     */
    public static byte[] privateKeyToPublicKey(byte[] privateKey, boolean compressed) {
        BigInteger privKey = requireValidPrivateKey(privateKey);
        ECPoint point = new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
        return point.getEncoded(compressed);
    }

    private static BigInteger requireValidPrivateKey(byte[] privateKey) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("Private key must be 32 bytes");
        }
        BigInteger privateScalar = new BigInteger(1, privateKey);
        if (privateScalar.signum() == 0 || privateScalar.compareTo(N) >= 0) {
            throw new IllegalArgumentException("Private key must be in the range [1, n - 1]");
        }
        return privateScalar;
    }

    /**
     * 解析派生路径
     */
    public static int[] parsePath(String path) {
        if (path == null || path.isEmpty()) {
            return new int[0];
        }

        String[] parts = path.split("/", -1);
        int startIndex = parts[0].equals("m") ? 1 : 0;
        int[] indices = new int[parts.length - startIndex];

        for (int i = startIndex; i < parts.length; i++) {
            String originalPart = parts[i];
            if (originalPart.isEmpty()) {
                throw new IllegalArgumentException("Derivation path contains an empty segment");
            }

            String part = originalPart;
            boolean hardened = part.endsWith("'") || part.endsWith("H");
            if (hardened) {
                part = part.substring(0, part.length() - 1);
            }

            if (part.isEmpty() || !isAsciiDecimal(part)) {
                throw new IllegalArgumentException("Invalid derivation path segment: " + originalPart);
            }

            final int indexValue;
            try {
                indexValue = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Derivation index out of range: " + originalPart, e);
            }

            int index = indexValue;
            if (hardened) {
                index |= 0x80000000;
            }
            indices[i - startIndex] = index;
        }

        return indices;
    }

    private static boolean isAsciiDecimal(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    /**
     * 将索引数组转为路径字符串
     */
    public static String indicesToPath(int[] indices) {
        StringBuilder sb = new StringBuilder("m");
        for (int index : indices) {
            sb.append("/");
            boolean hardened = (index & 0x80000000) != 0;
            int displayIndex = index & 0x7FFFFFFF;
            sb.append(displayIndex);
            if (hardened) {
                sb.append("'");
            }
        }
        return sb.toString();
    }

    private static byte[] hmacSha512(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA512 failed", e);
        }
    }

    /**
     * 扩展密钥记录
     */
    public static final class ExtendedKey implements AutoCloseable {

        private final byte[] privateKey;
        private final byte[] chainCode;
        private final int[] path;
        private final int depth;
        private volatile boolean destroyed = false;

        public ExtendedKey(byte[] privateKey, byte[] chainCode, int[] path, int depth) {
            if (privateKey == null || privateKey.length != 32) {
                throw new IllegalArgumentException("Private key must be 32 bytes");
            }
            if (chainCode == null || chainCode.length != 32) {
                throw new IllegalArgumentException("Chain code must be 32 bytes");
            }

            byte[] privateKeyCopy = SecureBytes.copy(privateKey);
            byte[] chainCodeCopy = SecureBytes.copy(chainCode);
            try {
                requireValidPrivateKey(privateKeyCopy);
                this.privateKey = privateKeyCopy;
                this.chainCode = chainCodeCopy;
                this.path = path == null ? new int[0] : Arrays.copyOf(path, path.length);
                this.depth = depth;
            } catch (RuntimeException | Error e) {
                SecureBytes.secureWipe(privateKeyCopy);
                SecureBytes.secureWipe(chainCodeCopy);
                throw e;
            }
        }

        /**
         * 获取公钥（压缩）
         */
        public synchronized byte[] getPublicKey() {
            checkNotDestroyed();
            return privateKeyToPublicKey(privateKey, true);
        }

        /**
         * 获取公钥（非压缩）
         */
        public synchronized byte[] getUncompressedPublicKey() {
            checkNotDestroyed();
            return privateKeyToPublicKey(privateKey, false);
        }

        /**
         * 获取私钥（返回副本）
         */
        public synchronized byte[] privateKey() {
            checkNotDestroyed();
            return SecureBytes.copy(privateKey);
        }

        /**
         * 获取链码（返回副本）
         */
        public synchronized byte[] chainCode() {
            checkNotDestroyed();
            return SecureBytes.copy(chainCode);
        }

        /**
         * 获取路径索引（返回副本）
         */
        public int[] path() {
            return Arrays.copyOf(path, path.length);
        }

        /**
         * 获取深度
         */
        public int depth() {
            return depth;
        }

        /**
         * 获取路径字符串
         */
        public String getPathString() {
            return indicesToPath(path);
        }

        /**
         * 安全销毁
         */
        public synchronized void destroy() {
            if (!destroyed) {
                SecureBytes.secureWipe(privateKey);
                SecureBytes.secureWipe(chainCode);
                destroyed = true;
            }
        }

        /**
         * AutoCloseable 支持
         */
        @Override
        public void close() {
            destroy();
        }

        /**
         * 是否已销毁
         */
        public boolean isDestroyed() {
            return destroyed;
        }

        private synchronized ExtendedKey copy() {
            checkNotDestroyed();
            return new ExtendedKey(privateKey, chainCode, path, depth);
        }

        private void checkNotDestroyed() {
            if (destroyed) {
                throw new IllegalStateException("Extended key has been destroyed");
            }
        }

        @Override
        public String toString() {
            return "ExtendedKey{***REDACTED***}";
        }
    }
}
