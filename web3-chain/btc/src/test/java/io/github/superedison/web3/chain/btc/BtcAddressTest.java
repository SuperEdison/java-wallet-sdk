package io.github.superedison.web3.chain.btc;

import io.github.superedison.web3.chain.btc.address.*;
import io.github.superedison.web3.crypto.ecc.Secp256k1Signer;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Bitcoin 地址测试
 */
class BtcAddressTest {

    // 测试向量 - 使用已知的测试私钥
    private static final byte[] TEST_PRIVATE_KEY = hexToBytes(
            "0000000000000000000000000000000000000000000000000000000000000001");

    // 已知地址（来自比特币测试向量）
    private static final String KNOWN_P2PKH_MAINNET = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    private static final String KNOWN_P2SH_MAINNET = "3CSUDH5yW1KHJmMDHfCCWShWPDN1pJwk5k";
    private static final String KNOWN_BECH32_MAINNET = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    private static final String KNOWN_TAPROOT_MAINNET = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

    @Test
    void testP2PKHAddressFromPublicKey() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            P2PKHAddress address = P2PKHAddress.fromPublicKey(publicKey, BtcNetwork.MAINNET);

            assertThat(address.getType()).isEqualTo(BtcAddressType.P2PKH);
            assertThat(address.getNetwork()).isEqualTo(BtcNetwork.MAINNET);
            assertThat(address.toBase58()).startsWith("1");
            assertThat(address.isValid()).isTrue();
        }
    }

    @Test
    void testP2PKHAddressRoundTrip() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            P2PKHAddress original = P2PKHAddress.fromPublicKey(publicKey, BtcNetwork.MAINNET);
            String encoded = original.toBase58();
            P2PKHAddress decoded = P2PKHAddress.fromBase58(encoded);

            assertThat(decoded.getHash()).isEqualTo(original.getHash());
            assertThat(decoded.getNetwork()).isEqualTo(original.getNetwork());
        }
    }

    @Test
    void testP2SHAddressFromPublicKey() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            P2SHAddress address = P2SHAddress.fromPublicKeyP2WPKH(publicKey, BtcNetwork.MAINNET);

            assertThat(address.getType()).isEqualTo(BtcAddressType.P2SH_P2WPKH);
            assertThat(address.getNetwork()).isEqualTo(BtcNetwork.MAINNET);
            assertThat(address.toBase58()).startsWith("3");
            assertThat(address.isValid()).isTrue();
        }
    }

    @Test
    void testP2SHAddressRoundTrip() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            P2SHAddress original = P2SHAddress.fromPublicKeyP2WPKH(publicKey, BtcNetwork.MAINNET);
            String encoded = original.toBase58();
            P2SHAddress decoded = P2SHAddress.fromBase58(encoded);

            assertThat(decoded.getHash()).isEqualTo(original.getHash());
        }
    }

    @Test
    void testBech32AddressFromPublicKey() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            Bech32Address address = Bech32Address.p2wpkhFromPublicKey(publicKey, BtcNetwork.MAINNET);

            assertThat(address.getType()).isEqualTo(BtcAddressType.P2WPKH);
            assertThat(address.getNetwork()).isEqualTo(BtcNetwork.MAINNET);
            assertThat(address.toBech32()).startsWith("bc1q");
            assertThat(address.getWitnessVersion()).isEqualTo(0);
            assertThat(address.isValid()).isTrue();
        }
    }

    @Test
    void testBech32AddressRoundTrip() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            Bech32Address original = Bech32Address.p2wpkhFromPublicKey(publicKey, BtcNetwork.MAINNET);
            String encoded = original.toBech32();
            Bech32Address decoded = Bech32Address.fromBech32(encoded);

            assertThat(decoded.getWitnessProgram()).isEqualTo(original.getWitnessProgram());
        }
    }

    @Test
    void testTaprootAddressFromPublicKey() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            TaprootAddress address = TaprootAddress.fromPublicKey(publicKey, BtcNetwork.MAINNET);

            assertThat(address.getType()).isEqualTo(BtcAddressType.P2TR);
            assertThat(address.getNetwork()).isEqualTo(BtcNetwork.MAINNET);
            assertThat(address.toBech32m()).startsWith("bc1p");
            assertThat(address.getWitnessVersion()).isEqualTo(1);
            assertThat(address.isValid()).isTrue();
        }
    }

    @Test
    void testTaprootAddressRoundTrip() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            TaprootAddress original = TaprootAddress.fromPublicKey(publicKey, BtcNetwork.MAINNET);
            String encoded = original.toBech32m();
            TaprootAddress decoded = TaprootAddress.fromBech32(encoded);

            assertThat(decoded.getOutputKey()).isEqualTo(original.getOutputKey());
        }
    }

    @Test
    void testBech32Encoding() {
        // 测试 BIP-173 中的测试向量
        byte[] witnessProgram = hexToBytes("751e76e8199196d454941c45d1b3a323f1433bd6");
        Bech32Address address = Bech32Address.fromWitnessProgram(0, witnessProgram, BtcNetwork.MAINNET);

        assertThat(address.toBech32().toLowerCase()).isEqualTo(KNOWN_BECH32_MAINNET);
    }

    @Test
    void testBech32Decoding() {
        Bech32Address address = Bech32Address.fromBech32(KNOWN_BECH32_MAINNET);

        assertThat(address.getWitnessVersion()).isEqualTo(0);
        assertThat(address.getWitnessProgram()).hasSize(20);
    }

    @Test
    void testAddressTypeDetection() {
        assertThat(BtcAddressType.fromAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"))
                .isEqualTo(BtcAddressType.P2PKH);
        assertThat(BtcAddressType.fromAddress("3CSUDH5yW1KHJmMDHfCCWShWPDN1pJwk5k"))
                .isEqualTo(BtcAddressType.P2SH_P2WPKH);
        assertThat(BtcAddressType.fromAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
                .isEqualTo(BtcAddressType.P2WPKH);
        assertThat(BtcAddressType.fromAddress("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"))
                .isEqualTo(BtcAddressType.P2TR);
    }

    @Test
    void testNetworkDetection() {
        assertThat(BtcNetwork.fromAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"))
                .isEqualTo(BtcNetwork.MAINNET);
        assertThat(BtcNetwork.fromAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
                .isEqualTo(BtcNetwork.MAINNET);
        assertThat(BtcNetwork.fromAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"))
                .isEqualTo(BtcNetwork.TESTNET);
        assertThat(BtcNetwork.fromAddress("mzBc4XEFSdzCDcTxAgf6EZXgsZWpztRhef"))
                .isEqualTo(BtcNetwork.TESTNET);
    }

    @Test
    void testTestnetAddresses() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            P2PKHAddress p2pkh = P2PKHAddress.fromPublicKey(publicKey, BtcNetwork.TESTNET);
            assertThat(p2pkh.toBase58().charAt(0)).isIn('m', 'n');

            P2SHAddress p2sh = P2SHAddress.fromPublicKeyP2WPKH(publicKey, BtcNetwork.TESTNET);
            assertThat(p2sh.toBase58()).startsWith("2");

            Bech32Address bech32 = Bech32Address.p2wpkhFromPublicKey(publicKey, BtcNetwork.TESTNET);
            assertThat(bech32.toBech32()).startsWith("tb1q");

            TaprootAddress taproot = TaprootAddress.fromPublicKey(publicKey, BtcNetwork.TESTNET);
            assertThat(taproot.toBech32m()).startsWith("tb1p");
        }
    }

    @Test
    void testScriptPubKey() {
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            // P2PKH scriptPubKey
            P2PKHAddress p2pkh = P2PKHAddress.fromPublicKey(publicKey, BtcNetwork.MAINNET);
            byte[] p2pkhScript = p2pkh.getScriptPubKey();
            assertThat(p2pkhScript).hasSize(25);
            assertThat(p2pkhScript[0]).isEqualTo((byte) 0x76); // OP_DUP
            assertThat(p2pkhScript[1]).isEqualTo((byte) 0xa9); // OP_HASH160

            // P2SH scriptPubKey
            P2SHAddress p2sh = P2SHAddress.fromPublicKeyP2WPKH(publicKey, BtcNetwork.MAINNET);
            byte[] p2shScript = p2sh.getScriptPubKey();
            assertThat(p2shScript).hasSize(23);
            assertThat(p2shScript[0]).isEqualTo((byte) 0xa9); // OP_HASH160

            // P2WPKH scriptPubKey
            Bech32Address bech32 = Bech32Address.p2wpkhFromPublicKey(publicKey, BtcNetwork.MAINNET);
            byte[] bech32Script = bech32.getScriptPubKey();
            assertThat(bech32Script).hasSize(22);
            assertThat(bech32Script[0]).isEqualTo((byte) 0x00); // OP_0

            // Taproot scriptPubKey
            TaprootAddress taproot = TaprootAddress.fromPublicKey(publicKey, BtcNetwork.MAINNET);
            byte[] taprootScript = taproot.getScriptPubKey();
            assertThat(taprootScript).hasSize(34);
            assertThat(taprootScript[0]).isEqualTo((byte) 0x51); // OP_1
        }
    }

    @Test
    void testAddressValidation() {
        // Valid Bech32 addresses (these are valid test vectors)
        assertThat(BtcAddress.isValid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")).isTrue();

        // Test with addresses we generate (known to be valid)
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();
            P2PKHAddress p2pkh = P2PKHAddress.fromPublicKey(publicKey, BtcNetwork.MAINNET);
            P2SHAddress p2sh = P2SHAddress.fromPublicKeyP2WPKH(publicKey, BtcNetwork.MAINNET);

            assertThat(BtcAddress.isValid(p2pkh.toBase58())).isTrue();
            assertThat(BtcAddress.isValid(p2sh.toBase58())).isTrue();
        }

        // Invalid addresses
        assertThat(BtcAddress.isValid("invalid")).isFalse();
        assertThat(BtcAddress.isValid("")).isFalse();
        assertThat(BtcAddress.isValid(null)).isFalse();
    }

    @Test
    void testUnifiedAddressParsing() {
        // 使用我们生成的有效地址进行测试
        try (Secp256k1Signer signer = new Secp256k1Signer(TEST_PRIVATE_KEY)) {
            byte[] publicKey = signer.getCompressedPublicKey();

            // 生成各类型地址
            P2PKHAddress generatedP2pkh = P2PKHAddress.fromPublicKey(publicKey, BtcNetwork.MAINNET);
            P2SHAddress generatedP2sh = P2SHAddress.fromPublicKeyP2WPKH(publicKey, BtcNetwork.MAINNET);
            Bech32Address generatedBech32 = Bech32Address.p2wpkhFromPublicKey(publicKey, BtcNetwork.MAINNET);

            // 从字符串解析
            BtcAddress p2pkh = BtcAddress.fromString(generatedP2pkh.toBase58());
            assertThat(p2pkh).isInstanceOf(P2PKHAddress.class);

            BtcAddress p2sh = BtcAddress.fromString(generatedP2sh.toBase58());
            assertThat(p2sh).isInstanceOf(P2SHAddress.class);

            BtcAddress bech32 = BtcAddress.fromString(generatedBech32.toBech32());
            assertThat(bech32).isInstanceOf(Bech32Address.class);
        }
    }

    @Test
    void testBase58CheckRoundTrip() {
        byte[] hash = new byte[20];
        for (int i = 0; i < 20; i++) {
            hash[i] = (byte) (i + 1);
        }

        String encoded = Base58Check.encodeChecked((byte) 0x00, hash);
        Base58Check.DecodedAddress decoded = Base58Check.decodeChecked(encoded);

        assertThat(decoded.version()).isEqualTo((byte) 0x00);
        assertThat(decoded.hash()).isEqualTo(hash);
    }

    @Test
    void testBase58CheckInvalidChecksum() {
        assertThatThrownBy(() -> Base58Check.decodeChecked("1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62x"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
