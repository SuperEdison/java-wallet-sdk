package io.github.superedison.web3.chain.evm.message;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.chain.evm.testutil.HighSSignatures;
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

@DisplayName("EVM 签名地址反算 (ecrecover)")
class EvmMessageSignerRecoverTest {

    private static final byte[] PRIVATE_KEY = new byte[]{
            (byte) 0x4c, (byte) 0x0d, (byte) 0xa4, (byte) 0xf3, (byte) 0x4d, (byte) 0x5f, (byte) 0x6a, (byte) 0x88,
            (byte) 0xc6, (byte) 0x9c, (byte) 0xa4, (byte) 0xe1, (byte) 0x4d, (byte) 0x52, (byte) 0x2c, (byte) 0x8e,
            (byte) 0xbb, (byte) 0xa1, (byte) 0x09, (byte) 0xb1, (byte) 0x2b, (byte) 0x07, (byte) 0x0d, (byte) 0x14,
            (byte) 0x9d, (byte) 0x6f, (byte) 0xb5, (byte) 0x52, (byte) 0xae, (byte) 0xa9, (byte) 0x16, (byte) 0x82
    };

    @Nested
    @DisplayName("EvmMessageSigner.recoverAddress")
    class RecoverFromMessage {

        @Test
        @DisplayName("EIP-191 sign 后 recover，地址等于签名者地址")
        void roundTripRecoversSigner() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                EvmAddress expected = EvmAddress.fromPublicKey(signer.getPublicKey());

                String message = "hello dapp";
                Signature sig = EvmMessageSigner.signMessage(message, signer);

                EvmAddress recovered = EvmMessageSigner.recoverAddress(message, sig);

                assertThat(recovered).isEqualTo(expected);
            }
        }

        @Test
        @DisplayName("byte[] 重载与 String 重载结果一致")
        void byteArrayAndStringOverloadsAgree() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                String message = "another message";
                Signature sig = EvmMessageSigner.signMessage(message, signer);

                EvmAddress fromString = EvmMessageSigner.recoverAddress(message, sig.bytes());
                EvmAddress fromBytes = EvmMessageSigner.recoverAddress(message.getBytes(), sig.bytes());

                assertThat(fromString).isEqualTo(fromBytes);
            }
        }

        @Test
        @DisplayName("拒绝可恢复同一地址的 high-S 紧凑签名")
        void rejectsHighSCompactSignature() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                String message = "reject malleable signature";
                Signature lowS = EvmMessageSigner.signMessage(message, signer);
                byte[] highS = HighSSignatures.fromCompact(lowS.bytes());

                assertThatThrownBy(() -> EvmMessageSigner.recoverAddress(message, highS))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("low-S");
                assertThat(EvmMessageSigner.verifyMessageAddress(
                        message, highS, EvmAddress.fromPublicKey(signer.getPublicKey()))).isFalse();
            }
        }

        @Test
        @DisplayName("消息签名拒绝 recovery-id 与 EIP-155 v 别名")
        void rejectsNonLegacyVAliases() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                String message = "canonical v";
                byte[] lowS = EvmMessageSigner.signMessage(message, signer).bytes();
                int recoveryId = (lowS[64] & 0xff) - 27;
                byte[] recoveryAlias = lowS.clone();
                recoveryAlias[64] = (byte) recoveryId;
                byte[] eip155Alias = lowS.clone();
                eip155Alias[64] = (byte) (37 + recoveryId);

                assertThatThrownBy(() -> EvmMessageSigner.recoverAddress(message, recoveryAlias))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("27 or 28");
                assertThatThrownBy(() -> EvmMessageSigner.recoverAddress(message, eip155Alias))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("27 or 28");
                assertThat(EvmMessageSigner.verifyMessage(
                        message.getBytes(StandardCharsets.UTF_8),
                        EvmSignature.fromCompact(recoveryAlias), signer.getPublicKey())).isFalse();
            }
        }
    }

    @Test
    @DisplayName("自定义 SigningKey 返回 high-S 时签名入口拒绝")
    void rejectsHighSFromSigningKey() {
        try (SigningKey signer = HighSSignatures.wrapping(new Secp256k1Signer(PRIVATE_KEY))) {
            assertThatThrownBy(() -> EvmMessageSigner.signMessage("high-s signer", signer))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("low-S");
        }
    }

    @Nested
    @DisplayName("EvmMessageSigner.verifyMessageAddress")
    class VerifyAgainstExpected {

        @Test
        @DisplayName("正确地址 → true")
        void returnsTrueForCorrectAddress() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                EvmAddress addr = EvmAddress.fromPublicKey(signer.getPublicKey());
                Signature sig = EvmMessageSigner.signMessage("hi", signer);

                assertThat(EvmMessageSigner.verifyMessageAddress("hi", sig.bytes(), addr)).isTrue();
            }
        }

        @Test
        @DisplayName("错误地址 → false")
        void returnsFalseForWrongAddress() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                Signature sig = EvmMessageSigner.signMessage("hi", signer);
                EvmAddress wrong = EvmAddress.fromHex("0x0000000000000000000000000000000000000001");

                assertThat(EvmMessageSigner.verifyMessageAddress("hi", sig.bytes(), wrong)).isFalse();
            }
        }

        @Test
        @DisplayName("expected 为 null → false，不抛异常")
        void returnsFalseForNullExpected() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                Signature sig = EvmMessageSigner.signMessage("hi", signer);

                assertThat(EvmMessageSigner.verifyMessageAddress("hi", sig.bytes(), null)).isFalse();
            }
        }

        @Test
        @DisplayName("非法签名字节 → false，不抛异常")
        void returnsFalseForCorruptedSignature() {
            EvmAddress any = EvmAddress.fromHex("0x0000000000000000000000000000000000000001");
            assertThat(EvmMessageSigner.verifyMessageAddress("hi", new byte[]{1, 2, 3}, any)).isFalse();
        }

        @Test
        @DisplayName("篡改消息 → false")
        void returnsFalseForTamperedMessage() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                EvmAddress addr = EvmAddress.fromPublicKey(signer.getPublicKey());
                Signature sig = EvmMessageSigner.signMessage("original", signer);

                assertThat(EvmMessageSigner.verifyMessageAddress("tampered", sig.bytes(), addr)).isFalse();
            }
        }
    }

    @Nested
    @DisplayName("EvmAddress.recover (基础层)")
    class RecoverFromHash {

        @Test
        @DisplayName("传 32 字节 hash + 65 字节签名 → 地址")
        void recoversFromRawHash() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                EvmAddress expected = EvmAddress.fromPublicKey(signer.getPublicKey());

                byte[] hash = new byte[32];
                for (int i = 0; i < 32; i++) hash[i] = (byte) i;
                Secp256k1Signer.Secp256k1Signature sig =
                        (Secp256k1Signer.Secp256k1Signature) signer.sign(hash);
                Signature evmSig = EvmSignature.fromRecoveryId(sig.r(), sig.s(), sig.v());
                EvmAddress recovered = EvmAddress.recover(hash, evmSig.bytes());

                assertThat(recovered).isEqualTo(expected);
            }
        }

        @Test
        @DisplayName("hash 长度错 → IllegalArgumentException")
        void rejectsWrongHashLength() {
            assertThatThrownBy(() -> EvmAddress.recover(new byte[10], new byte[65]))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("32 bytes");
        }

        @Test
        @DisplayName("签名长度错 → IllegalArgumentException")
        void rejectsWrongSignatureLength() {
            assertThatThrownBy(() -> EvmAddress.recover(new byte[32], new byte[10]))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("fromRecoveryId 不截断超长非零标量")
        void rejectsOversizedScalarInsteadOfTruncating() {
            byte[] oversizedR = new byte[33];
            oversizedR[0] = 1;
            byte[] s = new byte[32];
            s[31] = 1;

            assertThatThrownBy(() -> EvmSignature.fromRecoveryId(oversizedR, s, 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("does not fit");
        }

        @Test
        @DisplayName("fromRecoveryId 拒绝零标量与 r 等于曲线阶")
        void rejectsOutOfRangeScalars() {
            byte[] zero = new byte[32];
            byte[] one = new byte[32];
            one[31] = 1;
            byte[] curveOrder = HexFormat.of().parseHex(
                    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

            assertThatThrownBy(() -> EvmSignature.fromRecoveryId(zero, one, 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("r must be");
            assertThatThrownBy(() -> EvmSignature.fromRecoveryId(curveOrder, one, 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("r must be");
            assertThatThrownBy(() -> EvmSignature.fromRecoveryId(one, zero, 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("s must be");
        }

        @Test
        @DisplayName("fromRecoveryId 拒绝 compact v 无法表达的 2/3")
        void rejectsUnrepresentableRecoveryIds() {
            byte[] one = new byte[32];
            one[31] = 1;

            assertThatThrownBy(() -> EvmSignature.fromRecoveryId(one, one, 2))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("0 or 1");
            assertThatThrownBy(() -> EvmSignature.fromRecoveryId(one, one, 3))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("0 or 1");
        }
    }
}
