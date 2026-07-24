package io.github.superedison.web3.chain.tron.tip712;

import io.github.superedison.web3.chain.tron.address.TronAddress;
import io.github.superedison.web3.chain.tron.testutil.HighSSignatures;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.eip712.Eip712Domain;
import io.github.superedison.web3.crypto.eip712.Eip712Encoder;
import io.github.superedison.web3.crypto.eip712.Eip712TypedData;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TRON TIP-712 结构化数据签名")
class TronTypedDataSignerTest {

    private static final byte[] PRIVATE_KEY = new byte[]{
            (byte) 0x4c, (byte) 0x0d, (byte) 0xa4, (byte) 0xf3, (byte) 0x4d, (byte) 0x5f, (byte) 0x6a, (byte) 0x88,
            (byte) 0xc6, (byte) 0x9c, (byte) 0xa4, (byte) 0xe1, (byte) 0x4d, (byte) 0x52, (byte) 0x2c, (byte) 0x8e,
            (byte) 0xbb, (byte) 0xa1, (byte) 0x09, (byte) 0xb1, (byte) 0x2b, (byte) 0x07, (byte) 0x0d, (byte) 0x14,
            (byte) 0x9d, (byte) 0x6f, (byte) 0xb5, (byte) 0x52, (byte) 0xae, (byte) 0xa9, (byte) 0x16, (byte) 0x82
    };

    @Test
    @DisplayName("TRON codec 继续接受 base58 与 21 字节 0x41 地址")
    void tronAddressFormatsRemainSupported() {
        byte[] fromBase58 = TronTypedDataSigner.TRON_ADDRESS_CODEC
                .toAddress20("TUe6BwpA7sVTDKaJQoia7FWZpC9sK8WM2t");
        byte[] fromHex41 = TronTypedDataSigner.TRON_ADDRESS_CODEC
                .toAddress20("0x41" + "cc".repeat(20));

        assertThat(fromBase58).hasSize(20).isEqualTo(fromHex41);
    }

    @Nested
    @DisplayName("sign / verify / recover 往返（base58 地址）")
    class RoundTrip {

        private Eip712TypedData permit() {
            return Eip712TypedData.builder()
                    .domain(Eip712Domain.builder()
                            .name("USDT").version("1")
                            .chainId(TronTypedDataSigner.MAINNET_CHAIN_ID)
                            .verifyingContract("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
                            .build())
                    .addType("Permit",
                            new Eip712TypedData.Field("owner", "address"),
                            new Eip712TypedData.Field("spender", "address"),
                            new Eip712TypedData.Field("value", "uint256"),
                            new Eip712TypedData.Field("nonce", "uint256"),
                            new Eip712TypedData.Field("deadline", "uint256"))
                    .primaryType("Permit")
                    .message(Map.of(
                            "owner", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
                            "spender", "TUe6BwpA7sVTDKaJQoia7FWZpC9sK8WM2t",
                            "value", new BigInteger("1000000"),
                            "nonce", BigInteger.ZERO,
                            "deadline", new BigInteger("1893456000")))
                    .build();
        }

        @Test
        @DisplayName("sign 后 recover 得到签名者地址，verify 通过")
        void roundTrip() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                TronAddress expected = TronAddress.fromPublicKey(signer.getPublicKey());
                Signature sig = TronTypedDataSigner.signTypedData(permit(), signer);

                assertThat(sig.bytes()).hasSize(65);
                assertThat(TronTypedDataSigner.recoverAddress(permit(), sig)).isEqualTo(expected);
                assertThat(TronTypedDataSigner.verifyTypedData(permit(), sig, signer.getPublicKey())).isTrue();
                assertThat(TronTypedDataSigner.verifyTypedDataAddress(permit(), sig.bytes(), expected)).isTrue();

                // 64 字节裸公钥 (X||Y，无 0x04 前缀) 也应验签通过
                byte[] pub64 = java.util.Arrays.copyOfRange(signer.getPublicKey(), 1, 65);
                assertThat(TronTypedDataSigner.verifyTypedData(permit(), sig, pub64)).isTrue();
            }
        }

        @Test
        @DisplayName("recover 与地址验证拒绝 high-S 等价签名")
        void rejectsHighSSignature() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                TronAddress expected = TronAddress.fromPublicKey(signer.getPublicKey());
                byte[] highS = HighSSignatures.fromCompact(
                        TronTypedDataSigner.signTypedData(permit(), signer).bytes());

                assertThatThrownBy(() -> TronTypedDataSigner.recoverAddress(permit(), highS))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("low-S");
                assertThat(TronTypedDataSigner.verifyTypedDataAddress(permit(), highS, expected)).isFalse();
                assertThat(TronTypedDataSigner.verifyTypedData(
                        permit(), HighSSignatures.asSignature(highS), signer.getPublicKey())).isFalse();
            }
        }

        @Test
        @DisplayName("typed-data 签名拒绝 recovery-id 与 EIP-155 v 别名")
        void rejectsNonLegacyVAliases() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] lowS = TronTypedDataSigner.signTypedData(permit(), signer).bytes();
                int recoveryId = (lowS[64] & 0xff) - 27;
                byte[] recoveryAlias = lowS.clone();
                recoveryAlias[64] = (byte) recoveryId;
                byte[] eip155Alias = lowS.clone();
                eip155Alias[64] = (byte) (37 + recoveryId);

                assertThatThrownBy(() -> TronTypedDataSigner.recoverAddress(permit(), recoveryAlias))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("27 or 28");
                assertThatThrownBy(() -> TronTypedDataSigner.recoverAddress(permit(), eip155Alias))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("27 or 28");
                assertThat(TronTypedDataSigner.verifyTypedData(
                        permit(), HighSSignatures.asSignature(eip155Alias), signer.getPublicKey())).isFalse();
            }
        }
    }

    @Nested
    @DisplayName("Vector B — tronweb TrcToken Test（0x41 剥离 / trcToken / 数组 / 嵌套）")
    class VectorB {

        // 该向量特定 chainId（非主网），必须原样使用
        private static final BigInteger CHAIN_ID =
                new BigInteger("d698d4192c56cb6be724a558448e2684802de4d6cd8690dc", 16);
        private static final String VERIFYING = "TUe6BwpA7sVTDKaJQoia7FWZpC9sK8WM2t"; // 41cccc…cccc
        private static final String COW = "TUg28KYvCXWW81EqMUeZvCZmZw2BChk1HQ";       // 41cd2a…d826
        private static final String BOB = "TT5rFsXYCrnzdE2q1WdR9F2SuVY59A4hoM";       // 41bbbb…bbbb

        private Eip712TypedData mail() {
            return Eip712TypedData.builder()
                    .domain(Eip712Domain.builder()
                            .name("TrcToken Test").version("1").chainId(CHAIN_ID).verifyingContract(VERIFYING).build())
                    .addType("FromPerson",
                            new Eip712TypedData.Field("name", "string"),
                            new Eip712TypedData.Field("wallet", "address"),
                            new Eip712TypedData.Field("trcTokenId", "trcToken"))
                    .addType("ToPerson",
                            new Eip712TypedData.Field("name", "string"),
                            new Eip712TypedData.Field("wallet", "address"),
                            new Eip712TypedData.Field("trcTokenArr", "trcToken[]"))
                    .addType("Mail",
                            new Eip712TypedData.Field("from", "FromPerson"),
                            new Eip712TypedData.Field("to", "ToPerson"),
                            new Eip712TypedData.Field("contents", "string"),
                            new Eip712TypedData.Field("tAddr", "address[]"),
                            new Eip712TypedData.Field("trcTokenId", "trcToken"),
                            new Eip712TypedData.Field("trcTokenArr", "trcToken[]"))
                    .primaryType("Mail")
                    .message(Map.of(
                            "from", Map.of("name", "Cow", "wallet", COW, "trcTokenId", "1002000"),
                            "to", Map.of("name", "Bob", "wallet", BOB, "trcTokenArr", List.of("1002000", "1002000")),
                            "contents", "Hello, Bob!",
                            "tAddr", List.of(BOB, BOB),
                            "trcTokenId", "1002000",
                            "trcTokenArr", List.of("1002000", "1002000")))
                    .build();
        }

        @Test
        @DisplayName("domainSeparator / hashStruct(Mail) / digest 匹配 tronweb 断言值")
        void matchesTronwebVector() {
            Eip712Encoder enc = new Eip712Encoder(mail(), TronTypedDataSigner.TRON_ADDRESS_CODEC);
            assertThat(hex(enc.domainSeparator()))
                    .isEqualTo("0x23ce0ffcd4ff9a13936b4f1210884749acd9373a333dd7faa43f4045bb3aa1f7");
            assertThat(hex(enc.hashStruct("Mail", mail().message())))
                    .isEqualTo("0xf2f2a76e94f3c517b1e4c263854df0ef926aa17919b880a15d0ccf3ea121573c");
            assertThat(hex(TronTypedDataSigner.hashTypedData(mail())))
                    .isEqualTo("0x15a2ddfbd93ad048b6c1391659543b5e0dd5799cde747e219cbb07c2c3badd09");
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder("0x");
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
