package io.github.superedison.web3.chain.evm.eip712;

import io.github.superedison.web3.chain.evm.address.EvmAddress;
import io.github.superedison.web3.chain.evm.internal.EvmSignature;
import io.github.superedison.web3.chain.evm.testutil.HighSSignatures;
import io.github.superedison.web3.chain.exception.AddressException;
import io.github.superedison.web3.core.signer.Signature;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import io.github.superedison.web3.crypto.eip712.Eip712Domain;
import io.github.superedison.web3.crypto.eip712.Eip712TypedData;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("EVM EIP-712 结构化数据签名")
class EvmTypedDataSignerTest {

    private static final byte[] PRIVATE_KEY = new byte[]{
            (byte) 0x4c, (byte) 0x0d, (byte) 0xa4, (byte) 0xf3, (byte) 0x4d, (byte) 0x5f, (byte) 0x6a, (byte) 0x88,
            (byte) 0xc6, (byte) 0x9c, (byte) 0xa4, (byte) 0xe1, (byte) 0x4d, (byte) 0x52, (byte) 0x2c, (byte) 0x8e,
            (byte) 0xbb, (byte) 0xa1, (byte) 0x09, (byte) 0xb1, (byte) 0x2b, (byte) 0x07, (byte) 0x0d, (byte) 0x14,
            (byte) 0x9d, (byte) 0x6f, (byte) 0xb5, (byte) 0x52, (byte) 0xae, (byte) 0xa9, (byte) 0x16, (byte) 0x82
    };

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder("0x");
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        String h = hex.startsWith("0x") ? hex.substring(2) : hex;
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    @Nested
    @DisplayName("EVM 地址输入边界")
    class AddressValidation {

        @Test
        @DisplayName("拒绝 TRON 21 字节 0x41 地址，不静默重解释为 EVM 地址")
        void rejectsTronPrefixedAddresses() {
            String tronHex = "0x41" + "cc".repeat(20);
            byte[] tronBytes = hexToBytes(tronHex);

            assertThatThrownBy(() -> EvmTypedDataSigner.EVM_ADDRESS_CODEC.toAddress20(tronHex))
                    .isInstanceOf(AddressException.class);
            assertThatThrownBy(() -> EvmTypedDataSigner.EVM_ADDRESS_CODEC.toAddress20(tronBytes))
                    .isInstanceOf(AddressException.class);
        }

        @Test
        @DisplayName("仍接受规范 20 字节 EVM hex、byte[] 与 EvmAddress")
        void acceptsCanonicalEvmAddresses() {
            String hex = "0x" + "cc".repeat(20);
            byte[] bytes = hexToBytes(hex);
            EvmAddress address = EvmAddress.fromHex(hex);

            assertThat(EvmTypedDataSigner.EVM_ADDRESS_CODEC.toAddress20(hex)).isEqualTo(bytes);
            assertThat(EvmTypedDataSigner.EVM_ADDRESS_CODEC.toAddress20(bytes)).isEqualTo(bytes);
            assertThat(EvmTypedDataSigner.EVM_ADDRESS_CODEC.toAddress20(address)).isEqualTo(bytes);
        }

        @Test
        @DisplayName("混合大小写地址必须通过 EIP-55，行为与 ethers getAddress 一致")
        void validatesMixedCaseChecksum() {
            String valid = "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC";
            String invalid = "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccD";

            assertThat(EvmTypedDataSigner.EVM_ADDRESS_CODEC.toAddress20(valid))
                    .isEqualTo(EvmAddress.fromHex(valid).toBytes());
            assertThatThrownBy(() -> EvmTypedDataSigner.EVM_ADDRESS_CODEC.toAddress20(invalid))
                    .isInstanceOf(AddressException.class);
        }
    }

    /** EIP-712 规范经典 Mail 示例（用于对齐规范自带的 digest 与签名）。 */
    private static Eip712TypedData mail() {
        return Eip712TypedData.builder()
                .domain(Eip712Domain.builder()
                        .name("Ether Mail").version("1").chainId(1)
                        .verifyingContract("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
                        .build())
                .addType("Person",
                        new Eip712TypedData.Field("name", "string"),
                        new Eip712TypedData.Field("wallet", "address"))
                .addType("Mail",
                        new Eip712TypedData.Field("from", "Person"),
                        new Eip712TypedData.Field("to", "Person"),
                        new Eip712TypedData.Field("contents", "string"))
                .primaryType("Mail")
                .message(Map.of(
                        "from", Map.of("name", "Cow", "wallet", "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"),
                        "to", Map.of("name", "Bob", "wallet", "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
                        "contents", "Hello, Bob!"))
                .build();
    }

    @Nested
    @DisplayName("Vector A — 对齐 EIP-712 规范自带示例")
    class VectorA {

        @Test
        @DisplayName("digest 等于规范给出的签名摘要")
        void digestMatchesSpec() {
            assertThat(hex(EvmTypedDataSigner.hashTypedData(mail())))
                    .isEqualTo("0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
        }

        @Test
        @DisplayName("recover 出规范 eth_signTypedData 示例的签名者 0xCD2a…D826")
        void recoversSpecSigner() {
            // 规范 eth_signTypedData 示例返回的签名（r‖s‖v，v=0x1c）
            byte[] sig = hexToBytes(
                    "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d"
                            + "07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c");
            EvmAddress recovered = EvmTypedDataSigner.recoverAddress(mail(), sig);
            assertThat(recovered).isEqualTo(EvmAddress.fromHex("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"));
        }
    }

    @Nested
    @DisplayName("sign / verify / recover 往返")
    class RoundTrip {

        private Eip712TypedData permit() {
            return Eip712TypedData.builder()
                    .domain(Eip712Domain.builder()
                            .name("USD Coin").version("2").chainId(1)
                            .verifyingContract("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
                            .build())
                    .addType("Permit",
                            new Eip712TypedData.Field("owner", "address"),
                            new Eip712TypedData.Field("spender", "address"),
                            new Eip712TypedData.Field("value", "uint256"),
                            new Eip712TypedData.Field("nonce", "uint256"),
                            new Eip712TypedData.Field("deadline", "uint256"))
                    .primaryType("Permit")
                    .message(Map.of(
                            "owner", "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
                            "spender", "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
                            "value", new BigInteger("1000000"),
                            "nonce", BigInteger.ZERO,
                            "deadline", new BigInteger("1893456000")))
                    .build();
        }

        @Test
        @DisplayName("sign 后 recover 得到签名者地址，verify 通过")
        void roundTrip() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                EvmAddress expected = EvmAddress.fromPublicKey(signer.getPublicKey());
                Signature sig = EvmTypedDataSigner.signTypedData(permit(), signer);

                assertThat(sig.bytes()).hasSize(65);
                assertThat(EvmTypedDataSigner.recoverAddress(permit(), sig)).isEqualTo(expected);
                assertThat(EvmTypedDataSigner.verifyTypedData(permit(), sig, signer.getPublicKey())).isTrue();
                assertThat(EvmTypedDataSigner.verifyTypedDataAddress(permit(), sig.bytes(), expected)).isTrue();

                // 64 字节裸公钥 (X||Y，无 0x04 前缀) 也应验签通过
                byte[] pub64 = java.util.Arrays.copyOfRange(signer.getPublicKey(), 1, 65);
                assertThat(EvmTypedDataSigner.verifyTypedData(permit(), sig, pub64)).isTrue();
            }
        }

        @Test
        @DisplayName("recover 与地址验证拒绝 high-S 等价签名")
        void rejectsHighSSignature() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                EvmAddress expected = EvmAddress.fromPublicKey(signer.getPublicKey());
                byte[] highS = HighSSignatures.fromCompact(
                        EvmTypedDataSigner.signTypedData(permit(), signer).bytes());

                assertThatThrownBy(() -> EvmTypedDataSigner.recoverAddress(permit(), highS))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("low-S");
                assertThat(EvmTypedDataSigner.verifyTypedDataAddress(permit(), highS, expected)).isFalse();
            }
        }

        @Test
        @DisplayName("typed-data 签名拒绝 recovery-id 与 EIP-155 v 别名")
        void rejectsNonLegacyVAliases() {
            try (Secp256k1Signer signer = new Secp256k1Signer(PRIVATE_KEY)) {
                byte[] lowS = EvmTypedDataSigner.signTypedData(permit(), signer).bytes();
                int recoveryId = (lowS[64] & 0xff) - 27;
                byte[] recoveryAlias = lowS.clone();
                recoveryAlias[64] = (byte) recoveryId;
                byte[] eip155Alias = lowS.clone();
                eip155Alias[64] = (byte) (37 + recoveryId);

                assertThatThrownBy(() -> EvmTypedDataSigner.recoverAddress(permit(), recoveryAlias))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("27 or 28");
                assertThatThrownBy(() -> EvmTypedDataSigner.recoverAddress(permit(), eip155Alias))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessageContaining("27 or 28");
                assertThat(EvmTypedDataSigner.verifyTypedData(
                        permit(), EvmSignature.fromCompact(eip155Alias), signer.getPublicKey())).isFalse();
            }
        }
    }
}
