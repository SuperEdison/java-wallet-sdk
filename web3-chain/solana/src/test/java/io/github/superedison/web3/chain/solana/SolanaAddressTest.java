package io.github.superedison.web3.chain.solana;

import io.github.superedison.web3.chain.solana.address.Base58;
import io.github.superedison.web3.chain.solana.address.SolanaAddress;
import io.github.superedison.web3.crypto.ecc.Ed25519Signer;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Solana 地址测试
 */
class SolanaAddressTest {

    // 测试向量
    private static final String KNOWN_ADDRESS = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM";
    private static final String SYSTEM_PROGRAM = "11111111111111111111111111111111";

    @Test
    void testBase58Encode() {
        byte[] data = new byte[32];
        // 全零应该编码为 32 个 '1'
        String encoded = Base58.encode(data);
        assertThat(encoded).hasSize(32);
        assertThat(encoded).matches("1+");
    }

    @Test
    void testBase58Decode() {
        byte[] decoded = Base58.decode(SYSTEM_PROGRAM);
        assertThat(decoded).hasSize(32);
        assertThat(decoded).containsOnly((byte) 0);
    }

    @Test
    void testBase58RoundTrip() {
        byte[] original = new byte[32];
        for (int i = 0; i < 32; i++) {
            original[i] = (byte) i;
        }

        String encoded = Base58.encode(original);
        byte[] decoded = Base58.decode(encoded);

        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void testAddressFromBytes() {
        byte[] pubKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            pubKey[i] = (byte) (i + 1);
        }

        SolanaAddress address = SolanaAddress.fromBytes(pubKey);

        assertThat(address.toBytes()).isEqualTo(pubKey);
        assertThat(address.isValid()).isTrue();
    }

    @Test
    void testAddressFromBase58() {
        SolanaAddress address = SolanaAddress.fromBase58(KNOWN_ADDRESS);

        assertThat(address.toBase58()).isEqualTo(KNOWN_ADDRESS);
        assertThat(address.isValid()).isTrue();
    }

    @Test
    void testAddressFromPublicKey() {
        // 创建 Ed25519 密钥对
        byte[] privateKey = new byte[32];
        for (int i = 0; i < 32; i++) {
            privateKey[i] = (byte) (i + 100);
        }

        try (Ed25519Signer signer = new Ed25519Signer(privateKey)) {
            byte[] publicKey = signer.getPublicKey();

            SolanaAddress address = SolanaAddress.fromPublicKey(publicKey);

            // Solana 地址就是公钥本身
            assertThat(address.toBytes()).isEqualTo(publicKey);
        }
    }

    @Test
    void testAddressValidation() {
        assertThat(SolanaAddress.isValid(KNOWN_ADDRESS)).isTrue();
        assertThat(SolanaAddress.isValid(SYSTEM_PROGRAM)).isTrue();
        assertThat(SolanaAddress.isValid("invalid")).isFalse();
        assertThat(SolanaAddress.isValid("")).isFalse();
        assertThat(SolanaAddress.isValid(null)).isFalse();
    }

    @Test
    void testAddressEquality() {
        SolanaAddress addr1 = SolanaAddress.fromBase58(KNOWN_ADDRESS);
        SolanaAddress addr2 = SolanaAddress.fromBase58(KNOWN_ADDRESS);

        assertThat(addr1).isEqualTo(addr2);
        assertThat(addr1.hashCode()).isEqualTo(addr2.hashCode());
    }

    @Test
    void testInvalidAddressLength() {
        byte[] shortKey = new byte[20];

        assertThatThrownBy(() -> SolanaAddress.fromBytes(shortKey))
                .isInstanceOf(Exception.class);
    }

    @Test
    void testToHex() {
        SolanaAddress address = SolanaAddress.fromBase58(SYSTEM_PROGRAM);
        String hex = address.toHex();

        assertThat(hex).hasSize(64);
        assertThat(hex).matches("[0-9a-f]+");
    }
}
