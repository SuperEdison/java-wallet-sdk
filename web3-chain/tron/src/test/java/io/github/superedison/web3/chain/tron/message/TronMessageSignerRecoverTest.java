package io.github.superedison.web3.chain.tron.message;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("TRON 签名地址反算 (ecrecover)")
class TronMessageSignerRecoverTest {

    private static final byte[] PRIVATE_KEY = new byte[]{
            (byte) 0x4c, (byte) 0x0d, (byte) 0xa4, (byte) 0xf3, (byte) 0x4d, (byte) 0x5f, (byte) 0x6a, (byte) 0x88,
            (byte) 0xc6, (byte) 0x9c, (byte) 0xa4, (byte) 0xe1, (byte) 0x4d, (byte) 0x52, (byte) 0x2c, (byte) 0x8e,
            (byte) 0xbb, (byte) 0xa1, (byte) 0x09, (byte) 0xb1, (byte) 0x2b, (byte) 0x07, (byte) 0x0d, (byte) 0x14,
            (byte) 0x9d, (byte) 0x6f, (byte) 0xb5, (byte) 0x52, (byte) 0xae, (byte) 0xa9, (byte) 0x16, (byte) 0x82
    };

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
