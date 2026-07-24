package io.github.superedison.web3.crypto.kdf;

import io.github.superedison.web3.crypto.util.SecureBytes;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * SLIP-0010 实现（支持 Ed25519，常用于 Solana/NEAR/Aptos 等非 BIP-32 链）
 * 只支持 Hardened 派生。
 */
public final class Slip10 {

    private static final String ED25519_SEED_KEY = "ed25519 seed";

    private Slip10() {}

    public enum Curve {
        ED25519
    }

    /**
    * 从种子生成主密钥
    */
    public static ExtendedKey masterKeyFromSeed(byte[] seed, Curve curve) {
        if (curve == null) {
            throw new IllegalArgumentException("Curve cannot be null");
        }
        String key = switch (curve) {
            case ED25519 -> ED25519_SEED_KEY;
        };
        byte[] i = hmacSha512(key.getBytes(StandardCharsets.UTF_8), seed);
        byte[] kL = null;
        byte[] chainCode = null;
        try {
            kL = Arrays.copyOfRange(i, 0, 32);
            chainCode = Arrays.copyOfRange(i, 32, 64);
            return new ExtendedKey(curve, kL, chainCode, new int[0], 0);
        } finally {
            SecureBytes.secureWipe(i);
            SecureBytes.secureWipe(kL);
            SecureBytes.secureWipe(chainCode);
        }
    }

    /**
     * 派生子密钥（只支持 Hardened，index 必须带 0x80000000）
     */
    public static ExtendedKey deriveChild(ExtendedKey parent, int index) {
        if (parent == null) {
            throw new IllegalArgumentException("Parent key cannot be null");
        }

        synchronized (parent) {
            parent.checkNotDestroyed();

            if ((index & 0x80000000) == 0) {
                throw new IllegalArgumentException("SLIP-0010 Ed25519 only supports hardened derivation");
            }
            byte[] data = new byte[1 + 32 + 4];
            try {
                data[0] = 0x00;
                System.arraycopy(parent.key, 0, data, 1, 32);
                ByteBuffer.wrap(data, 33, 4).putInt(index);

                byte[] i = hmacSha512(parent.chainCode, data);
                byte[] childKey = null;
                byte[] childChainCode = null;
                try {
                    childKey = Arrays.copyOfRange(i, 0, 32);
                    childChainCode = Arrays.copyOfRange(i, 32, 64);

                    int[] newPath = Arrays.copyOf(parent.path, parent.path.length + 1);
                    newPath[newPath.length - 1] = index;
                    return new ExtendedKey(parent.curve, childKey, childChainCode, newPath, parent.depth + 1);
                } finally {
                    SecureBytes.secureWipe(i);
                    SecureBytes.secureWipe(childKey);
                    SecureBytes.secureWipe(childChainCode);
                }
            } finally {
                SecureBytes.secureWipe(data);
            }
        }
    }

    /**
     * 按路径派生，例如 m/44'/501'/0'/0'
     */
    public static ExtendedKey derivePath(ExtendedKey master, String path) {
        if (master == null) {
            throw new IllegalArgumentException("Master key cannot be null");
        }
        master.checkNotDestroyed();

        int[] indices = Bip32.parsePath(path); // 复用解析逻辑
        for (int index : indices) {
            if ((index & 0x80000000) == 0) {
                throw new IllegalArgumentException("SLIP-0010 Ed25519 only supports hardened derivation");
            }
        }

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
     * 扩展密钥（Ed25519）
     */
    public static final class ExtendedKey implements AutoCloseable {
        private final Curve curve;
        private final byte[] key;
        private final byte[] chainCode;
        private final int[] path;
        private final int depth;
        private volatile boolean destroyed = false;

        public ExtendedKey(Curve curve, byte[] key, byte[] chainCode, int[] path, int depth) {
            if (curve == null) {
                throw new IllegalArgumentException("Curve cannot be null");
            }
            if (key == null || key.length != 32) {
                throw new IllegalArgumentException("Private key must be 32 bytes");
            }
            if (chainCode == null || chainCode.length != 32) {
                throw new IllegalArgumentException("Chain code must be 32 bytes");
            }

            byte[] keyCopy = SecureBytes.copy(key);
            byte[] chainCodeCopy = SecureBytes.copy(chainCode);
            try {
                this.curve = curve;
                this.key = keyCopy;
                this.chainCode = chainCodeCopy;
                this.path = path == null ? new int[0] : Arrays.copyOf(path, path.length);
                this.depth = depth;
            } catch (RuntimeException | Error e) {
                SecureBytes.secureWipe(keyCopy);
                SecureBytes.secureWipe(chainCodeCopy);
                throw e;
            }
        }

        public Curve getCurve() {
            return curve;
        }

        /**
         * 返回私钥 seed（32 字节，副本）
         */
        public synchronized byte[] getKey() {
            checkNotDestroyed();
            return SecureBytes.copy(key);
        }

        /**
         * 链码（副本）
         */
        public synchronized byte[] getChainCode() {
            checkNotDestroyed();
            return SecureBytes.copy(chainCode);
        }

        /**
         * 路径索引（副本）
         */
        public int[] path() {
            return Arrays.copyOf(path, path.length);
        }

        public int depth() {
            return depth;
        }

        public String getPathString() {
            return Bip32.indicesToPath(path);
        }

        public synchronized void destroy() {
            if (!destroyed) {
                SecureBytes.secureWipe(key);
                SecureBytes.secureWipe(chainCode);
                destroyed = true;
            }
        }

        @Override
        public void close() {
            destroy();
        }

        public boolean isDestroyed() {
            return destroyed;
        }

        private synchronized ExtendedKey copy() {
            checkNotDestroyed();
            return new ExtendedKey(curve, key, chainCode, path, depth);
        }

        private void checkNotDestroyed() {
            if (destroyed) {
                throw new IllegalStateException("Extended key has been destroyed");
            }
        }

        @Override
        public String toString() {
            return "Slip10ExtendedKey{***REDACTED***}";
        }
    }
}
