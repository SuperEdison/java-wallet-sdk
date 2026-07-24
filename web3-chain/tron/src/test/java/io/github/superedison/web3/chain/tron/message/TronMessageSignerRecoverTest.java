package io.github.superedison.web3.chain.tron.message;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.chain.tron.internal.TronSignature;
import io.github.superedison.web3.chain.tron.testutil.HighSSignatures;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.core.signer.SigningKey;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TRON 签名地址反算 (ecrecover)")
class TronMessageSignerRecoverTest {

    private static final byte[] PRIVATE_KEY = new byte[]{
            (byte) 0x4c, (byte) 0x0d, (byte) 0xa4, (byte) 0xf3, (byte) 0x4d, (byte) 0x5f, (byte) 0x6a, (byte) 0x88,
            (byte) 0xc6, (byte) 0x9c, (byte) 0xa4, (byte) 0xe1, (byte) 0x4d, (byte) 0x52, (byte) 0x2c, (byte) 0x8e,
            (byte) 0xbb, (byte) 0xa1, (byte) 0x09, (byte) 0xb1, (byte) 0x2b, (byte) 0x07, (byte) 0x0d, (byte) 0x14,
            (byte) 0x9d, (byte) 0x6f, (byte) 0xb5, (byte) 0x52, (byte) 0xae, (byte) 0xa9, (byte) 0x16, (byte) 0x82
    };

    @Nested
    @DisplayName("TronWeb signMessageV2 兼容向量")
    class TronWebV2Compatibility {

        private final byte[] message = "hello".getBytes(StandardCharsets.UTF_8);

        @Test
        @DisplayName("预映像只包含一个 0x19 前缀")
        void preimageMatchesTronWeb() {
            assertThat(TronMessageSigner.messagePreimage(message)).isEqualTo(HexFormat.of().parseHex(
                    "1954524f4e205369676e6564204d6573736167653a0a3568656c6c6f"));
        }

        @Test
        @DisplayName("hash 与 TronWeb 6.4.0 hashMessage 固定向量一致")
        void hashMatchesTronWeb() {
            assertThat(TronMessageSigner.hashMessage(message)).isEqualTo(HexFormat.of().parseHex(
                    "a07d8e5b946cc0416662f5420751673680809e5f10313e20c7c5badb0ef4226d"));
        }

        @Test
        @DisplayName("String 重载拒绝未配对 surrogate，不产生 UTF-8 替换碰撞")
        void rejectsMalformedUtf16() {
            String loneHigh = String.valueOf((char) 0xD800);
            String loneLow = String.valueOf((char) 0xDC00);

            assertThatThrownBy(() -> TronMessageSigner.hashMessage(loneHigh))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> TronMessageSigner.hashMessage(loneLow))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("合法 surrogate pair 与 UTF-8 byte[] 重载一致")
        void validSurrogatePairMatchesBytes() {
            String emoji = new String(Character.toChars(0x1F600));
            assertThat(TronMessageSigner.hashMessage(emoji))
                    .isEqualTo(TronMessageSigner.hashMessage(emoji.getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Nested
    @DisplayName("TronMessageSigner.recoverAddress")
    class RecoverFromMessage {

        @Test
        @DisplayName("sign 后 recover，地址等于签名者地址")
        void roundTripRecoversSigner() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                TronAddress expected = TronAddress.fromPublicKey(signer.getPublicKey());

                String message = "hello tron";
                Signature sig = TronMessageSigner.signMessage(message, signer);

                TronAddress recovered = TronMessageSigner.recoverAddress(message, sig);

                assertThat(recovered).isEqualTo(expected);
            }
        }

        @Test
        @DisplayName("byte[] 重载与 String 重载结果一致")
        void byteArrayAndStringOverloadsAgree() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                String message = "round trip";
                Signature sig = TronMessageSigner.signMessage(message, signer);

                TronAddress fromString = TronMessageSigner.recoverAddress(message, sig.bytes());
                TronAddress fromBytes = TronMessageSigner.recoverAddress(message.getBytes(), sig.bytes());

                assertThat(fromString).isEqualTo(fromBytes);
            }
        }

        @Test
        @DisplayName("拒绝可恢复同一地址的 high-S 紧凑签名")
        void rejectsHighSCompactSignature() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                String message = "reject malleable signature";
                Signature lowS = TronMessageSigner.signMessage(message, signer);
                byte[] highS = HighSSignatures.fromCompact(lowS.bytes());

                assertThatThrownBy(() -> TronMessageSigner.recoverAddress(message, highS))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("low-S");
                assertThat(TronMessageSigner.verifyMessageAddress(
                        message, highS, TronAddress.fromPublicKey(signer.getPublicKey()))).isFalse();
                assertThat(TronMessageSigner.verifyMessage(
                        message, HighSSignatures.asSignature(highS), signer.getPublicKey())).isFalse();
            }
        }

        @Test
        @DisplayName("消息签名拒绝 recovery-id 与 EIP-155 v 别名")
        void rejectsNonLegacyVAliases() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                String message = "canonical v";
                byte[] lowS = TronMessageSigner.signMessage(message, signer).bytes();
                int recoveryId = (lowS[64] & 0xff) - 27;
                byte[] recoveryAlias = lowS.clone();
                recoveryAlias[64] = (byte) recoveryId;
                byte[] eip155Alias = lowS.clone();
                eip155Alias[64] = (byte) (37 + recoveryId);

                assertThatThrownBy(() -> TronMessageSigner.recoverAddress(message, recoveryAlias))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("27 or 28");
                assertThatThrownBy(() -> TronMessageSigner.recoverAddress(message, eip155Alias))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("27 or 28");
                assertThat(TronMessageSigner.verifyMessage(
                        message, HighSSignatures.asSignature(recoveryAlias), signer.getPublicKey())).isFalse();
            }
        }
    }

    @Test
    @DisplayName("自定义 SigningKey 返回 high-S 时签名入口拒绝")
    void rejectsHighSFromSigningKey() {
        try (SigningKey signer = HighSSignatures.wrapping(new Secp256k1Signer(PRIVATE_KEY))) {
            assertThatThrownBy(() -> TronMessageSigner.signMessage("high-s signer", signer))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("low-S");
        }
    }

    @Test
    @DisplayName("fromRecoveryId 拒绝 compact v 无法表达的 2/3")
    void rejectsUnrepresentableRecoveryIds() {
        byte[] one = new byte[32];
        one[31] = 1;

        assertThatThrownBy(() -> TronSignature.fromRecoveryId(one, one, 2))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("0 or 1");
        assertThatThrownBy(() -> TronSignature.fromRecoveryId(one, one, 3))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("0 or 1");
    }

    @Nested
    @DisplayName("TronMessageSigner.verifyMessageAddress")
    class VerifyAgainstExpected {

        @Test
        @DisplayName("正确地址 → true")
        void returnsTrueForCorrectAddress() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                TronAddress addr = TronAddress.fromPublicKey(signer.getPublicKey());
                Signature sig = TronMessageSigner.signMessage("hi", signer);

                assertThat(TronMessageSigner.verifyMessageAddress("hi", sig.bytes(), addr)).isTrue();
            }
        }

        @Test
        @DisplayName("expected 为 null → false")
        void returnsFalseForNullExpected() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                Signature sig = TronMessageSigner.signMessage("hi", signer);
                assertThat(TronMessageSigner.verifyMessageAddress("hi", sig.bytes(), null)).isFalse();
            }
        }

        @Test
        @DisplayName("非法签名字节 → false，不抛异常")
        void returnsFalseForCorruptedSignature() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                TronAddress addr = TronAddress.fromPublicKey(signer.getPublicKey());
                assertThat(TronMessageSigner.verifyMessageAddress("hi", new byte[]{1, 2, 3}, addr)).isFalse();
            }
        }

        @Test
        @DisplayName("篡改消息 → false")
        void returnsFalseForTamperedMessage() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                TronAddress addr = TronAddress.fromPublicKey(signer.getPublicKey());
                Signature sig = TronMessageSigner.signMessage("original", signer);

                assertThat(TronMessageSigner.verifyMessageAddress("tampered", sig.bytes(), addr)).isFalse();
            }
        }
    }
}
