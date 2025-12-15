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
        byte[] privateKey = Arrays.copyOfRange(hmac, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(hmac, 32, 64);

        // 验证私钥有效性
        BigInteger key = new BigInteger(1, privateKey);
        if (key.equals(BigInteger.ZERO) || key.compareTo(N) >= 0) {
            throw new IllegalStateException("Invalid master key derived");
        }

        return new ExtendedKey(privateKey, chainCode, new int[0], 0);
    }

    /**
     * 派生子密钥
     * @param parent 父扩展密钥
     * @param index 索引 (0x80000000 以上为硬化派生)
     * @return 子扩展密钥
     */
    public static ExtendedKey deriveChild(ExtendedKey parent, int index) {
        byte[] data;
        boolean hardened = (index & 0x80000000) != 0;

        if (hardened) {
            // 硬化派生: HMAC-SHA512(chainCode, 0x00 || privateKey || index)
            data = new byte[37];
            data[0] = 0x00;
            System.arraycopy(parent.privateKey(), 0, data, 1, 32);
            ByteBuffer.wrap(data, 33, 4).putInt(index);
        } else {
            // 普通派生: HMAC-SHA512(chainCode, publicKey || index)
            byte[] publicKey = privateKeyToPublicKey(parent.privateKey(), true);
            data = new byte[37];
            System.arraycopy(publicKey, 0, data, 0, 33);
            ByteBuffer.wrap(data, 33, 4).putInt(index);
        }

        byte[] hmac = hmacSha512(parent.chainCode(), data);
        byte[] il = Arrays.copyOfRange(hmac, 0, 32);
        byte[] childChainCode = Arrays.copyOfRange(hmac, 32, 64);

        // 计算子私钥: (il + parentKey) mod n
        BigInteger ilInt = new BigInteger(1, il);
        BigInteger parentKeyInt = new BigInteger(1, parent.privateKey());
        BigInteger childKeyInt = ilInt.add(parentKeyInt).mod(N);

        if (ilInt.compareTo(N) >= 0 || childKeyInt.equals(BigInteger.ZERO)) {
            // 无效密钥，尝试下一个索引
            return deriveChild(parent, index + 1);
        }

        byte[] childPrivateKey = SecureBytes.padLeft(childKeyInt.toByteArray(), 32);

        int[] newPath = new int[parent.path().length + 1];
        System.arraycopy(parent.path(), 0, newPath, 0, parent.path().length);
        newPath[newPath.length - 1] = index;

        return new ExtendedKey(childPrivateKey, childChainCode, newPath, parent.depth() + 1);
    }

    /**
     * 按路径派生密钥
     * @param master 主密钥
     * @param path 派生路径，如 "m/44'/60'/0'/0/0"
     * @return 派生的扩展密钥
     */
    public static ExtendedKey derivePath(ExtendedKey master, String path) {
        int[] indices = parsePath(path);
        ExtendedKey current = master;
        for (int index : indices) {
            current = deriveChild(current, index);
        }
        return current;
    }

    /**
     * 从种子按路径派生密钥
     */
    public static ExtendedKey derivePath(byte[] seed, String path) {
        return derivePath(masterKeyFromSeed(seed), path);
    }

    /**
     * 私钥转公钥
     */
    public static byte[] privateKeyToPublicKey(byte[] privateKey, boolean compressed) {
        BigInteger privKey = new BigInteger(1, privateKey);
        ECPoint point = new FixedPointCombMultiplier().multiply(CURVE.getG(), privKey);
        return point.getEncoded(compressed);
    }

    /**
     * 解析派生路径
     */
    public static int[] parsePath(String path) {
        if (path == null || path.isEmpty()) {
            return new int[0];
        }

        String[] parts = path.split("/");
        int startIndex = parts[0].equals("m") ? 1 : 0;
        int[] indices = new int[parts.length - startIndex];

        for (int i = startIndex; i < parts.length; i++) {
            String part = parts[i];
            boolean hardened = part.endsWith("'") || part.endsWith("H");
            if (hardened) {
                part = part.substring(0, part.length() - 1);
            }
            int index = Integer.parseInt(part);
            if (hardened) {
                index |= 0x80000000;
            }
            indices[i - startIndex] = index;
        }

        return indices;
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
        private boolean destroyed = false;

        public ExtendedKey(byte[] privateKey, byte[] chainCode, int[] path, int depth) {
            this.privateKey = SecureBytes.copy(privateKey);
            this.chainCode = SecureBytes.copy(chainCode);
            this.path = path == null ? new int[0] : Arrays.copyOf(path, path.length);
            this.depth = depth;
        }

        /**
         * 获取公钥（压缩）
         */
        public byte[] getPublicKey() {
            return privateKeyToPublicKey(privateKey, true);
        }

        /**
         * 获取公钥（非压缩）
         */
        public byte[] getUncompressedPublicKey() {
            return privateKeyToPublicKey(privateKey, false);
        }

        /**
         * 获取私钥（返回副本）
         */
        public byte[] privateKey() {
            return SecureBytes.copy(privateKey);
        }

        /**
         * 获取链码（返回副本）
         */
        public byte[] chainCode() {
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
        public void destroy() {
            SecureBytes.secureWipe(privateKey);
            SecureBytes.wipe(chainCode);
            destroyed = true;
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

        @Override
        public String toString() {
            return "ExtendedKey{***REDACTED***}";
        }
    }
}
