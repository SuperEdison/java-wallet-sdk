package io.github.superedison.web3.kms;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * 解析云 KMS 返回的 DER 编码 ECDSA 签名。
 *
 * AWS KMS / GCP KMS 对 secp256k1 与 secp256r1 都返回
 *   SEQUENCE { INTEGER r, INTEGER s }
 * 这里只做"解码 + low-S 规范化"，恢复 id 由调用方用公钥反算。
 */
public final class DerSignatures {

    private static final BigInteger SECP256K1_N =
            CustomNamedCurves.getByName("secp256k1").getN();
    private static final BigInteger SECP256K1_HALF_N = SECP256K1_N.shiftRight(1);

    private DerSignatures() {}

    public record RS(BigInteger r, BigInteger s) {}

    /**
     * 解析 DER 编码的 ECDSA 签名 → (r, s)。
     */
    public static RS parse(byte[] der) {
        if (der == null || der.length == 0) {
            throw new IllegalArgumentException("DER signature must not be empty");
        }
        try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(der))) {
            ASN1Sequence seq = ASN1Sequence.getInstance(in.readObject());
            if (seq.size() != 2) {
                throw new IllegalArgumentException("DER signature must contain exactly r and s");
            }
            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            if (r.signum() <= 0 || s.signum() <= 0) {
                throw new IllegalArgumentException("r and s must be positive");
            }
            return new RS(r, s);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to parse DER signature", e);
        }
    }

    /**
     * EIP-2 / BIP-66 低-S 规范化（secp256k1）。
     * 若 s > N/2，则 s := N - s。
     */
    public static BigInteger normalizeLowS(BigInteger s) {
        if (s.compareTo(SECP256K1_HALF_N) > 0) {
            return SECP256K1_N.subtract(s);
        }
        return s;
    }

    /**
     * 32 字节左零填充。
     */
    public static byte[] toFixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == 32) {
            return raw;
        }
        byte[] out = new byte[32];
        if (raw.length < 32) {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        } else {
            // 去掉 BigInteger 的符号字节
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        }
        return out;
    }
}
