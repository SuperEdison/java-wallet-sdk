package io.github.superedison.web3.kms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECPoint;

/**
 * 解析云 KMS 返回的 X.509 SubjectPublicKeyInfo (DER)，
 * 取出链上需要的原始公钥字节。
 *
 * 输入示例（AWS / GCP 的 GetPublicKey 都返回同一种结构）：
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *       algorithm        AlgorithmIdentifier,
 *       subjectPublicKey BIT STRING
 *   }
 */
public final class SubjectPublicKeyInfos {

    /** Ed25519 算法 OID，RFC 8410。 */
    private static final ASN1ObjectIdentifier OID_ED25519 =
            new ASN1ObjectIdentifier("1.3.101.112");

    private static final X9ECParameters SECP256K1 =
            CustomNamedCurves.getByName("secp256k1");

    private SubjectPublicKeyInfos() {}

    /**
     * 解析 secp256k1 公钥 → 65 字节非压缩格式 (04 || X || Y)。
     */
    public static byte[] parseSecp256k1Uncompressed(byte[] spkiDer) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiDer);
        ASN1ObjectIdentifier algo = spki.getAlgorithm().getAlgorithm();
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algo)) {
            throw new IllegalArgumentException("Not an EC public key: " + algo);
        }
        ASN1ObjectIdentifier curve = ASN1ObjectIdentifier.getInstance(spki.getAlgorithm().getParameters());
        if (!SECObjectIdentifiers.secp256k1.equals(curve)) {
            throw new IllegalArgumentException("Curve is not secp256k1: " + curve);
        }
        byte[] point = spki.getPublicKeyData().getBytes();
        // KMS 可能返回压缩或非压缩；统一解码后输出非压缩 65 字节。
        ECPoint decoded = SECP256K1.getCurve().decodePoint(point);
        return decoded.getEncoded(false);
    }

    /**
     * 解析 Ed25519 公钥 → 32 字节原始。
     */
    public static byte[] parseEd25519(byte[] spkiDer) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiDer);
        ASN1ObjectIdentifier algo = spki.getAlgorithm().getAlgorithm();
        if (!OID_ED25519.equals(algo)) {
            throw new IllegalArgumentException("Not an Ed25519 public key: " + algo);
        }
        byte[] raw = spki.getPublicKeyData().getBytes();
        if (raw.length != 32) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes, got " + raw.length);
        }
        return raw;
    }
}
