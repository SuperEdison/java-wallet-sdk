package io.github.superedison.web3.crypto.kdf;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("BIP-32 regression tests")
class Bip32Test {

    private static final byte[] VECTOR_SEED =
            HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
    private static final String MASTER_PRIVATE_KEY =
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    private static final String MASTER_CHAIN_CODE =
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
    private static final String FIRST_HARDENED_PRIVATE_KEY =
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
    private static final String FIRST_HARDENED_CHAIN_CODE =
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";

    @Test
    @DisplayName("master key matches the official test vector")
    void derivesOfficialMasterVector() {
        try (Bip32.ExtendedKey master = Bip32.masterKeyFromSeed(VECTOR_SEED)) {
            assertThat(HexFormat.of().formatHex(master.privateKey())).isEqualTo(MASTER_PRIVATE_KEY);
            assertThat(HexFormat.of().formatHex(master.chainCode())).isEqualTo(MASTER_CHAIN_CODE);
        }
    }

    @Test
    @DisplayName("child key remains intact after temporary derivation buffers are wiped")
    void derivesOfficialFirstHardenedChildVector() {
        try (Bip32.ExtendedKey master = Bip32.masterKeyFromSeed(VECTOR_SEED);
             Bip32.ExtendedKey child = Bip32.deriveChild(master, 0x80000000)) {
            assertThat(HexFormat.of().formatHex(child.privateKey()))
                    .isEqualTo(FIRST_HARDENED_PRIVATE_KEY);
            assertThat(HexFormat.of().formatHex(child.chainCode()))
                    .isEqualTo(FIRST_HARDENED_CHAIN_CODE);
            assertThat(child.getPathString()).isEqualTo("m/0'");
        }
    }

    @Test
    @DisplayName("root path aliases return independent key objects")
    void rootPathReturnsIndependentCopies() {
        try (Bip32.ExtendedKey master = Bip32.masterKeyFromSeed(VECTOR_SEED);
             Bip32.ExtendedKey fromM = Bip32.derivePath(master, "m");
             Bip32.ExtendedKey fromEmpty = Bip32.derivePath(master, "");
             Bip32.ExtendedKey fromNull = Bip32.derivePath(master, null)) {

            assertThat(fromM).isNotSameAs(master);
            assertThat(fromEmpty).isNotSameAs(master);
            assertThat(fromNull).isNotSameAs(master);
            assertThat(fromM.privateKey()).isEqualTo(master.privateKey());
            assertThat(fromEmpty.privateKey()).isEqualTo(master.privateKey());
            assertThat(fromNull.privateKey()).isEqualTo(master.privateKey());

            fromM.destroy();
            assertThat(master.isDestroyed()).isFalse();
            assertThat(HexFormat.of().formatHex(master.privateKey())).isEqualTo(MASTER_PRIVATE_KEY);
        }
    }

    @Test
    @DisplayName("seed overload keeps the returned root key alive")
    void seedOverloadReturnsLiveRootCopy() {
        try (Bip32.ExtendedKey root = Bip32.derivePath(VECTOR_SEED, "m")) {
            assertThat(root.isDestroyed()).isFalse();
            assertThat(HexFormat.of().formatHex(root.privateKey())).isEqualTo(MASTER_PRIVATE_KEY);
            assertThat(HexFormat.of().formatHex(root.chainCode())).isEqualTo(MASTER_CHAIN_CODE);
        }
    }

    @Test
    @DisplayName("destroyed master key cannot be copied, read, or derived")
    void rejectsDestroyedMasterKey() {
        Bip32.ExtendedKey master = Bip32.masterKeyFromSeed(VECTOR_SEED);
        master.destroy();

        assertThatThrownBy(() -> Bip32.derivePath(master, "m"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> Bip32.derivePath(master, ""))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> Bip32.deriveChild(master, 0x80000000))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(master::privateKey).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(master::chainCode).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(master::getPublicKey).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("parser rejects empty segments, signs, and out-of-range indexes")
    void rejectsNonCanonicalPaths() {
        assertThat(Bip32.parsePath(null)).isEmpty();
        assertThat(Bip32.parsePath("")).isEmpty();
        assertThat(Bip32.parsePath("m")).isEmpty();

        assertThatThrownBy(() -> Bip32.parsePath("m/"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Bip32.parsePath("m//0"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Bip32.parsePath("/0"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Bip32.parsePath("m/-1"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Bip32.parsePath("m/+1"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Bip32.parsePath("m/2147483648"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("parser preserves supported absolute and relative paths")
    void parsesSupportedPaths() {
        assertThat(Bip32.parsePath("m/44'/60H/0/2147483647")).containsExactly(
                0x8000002c, 0x8000003c, 0, 0x7fffffff);
        assertThat(Bip32.parsePath("44'/60'/0'/0/0")).containsExactly(
                0x8000002c, 0x8000003c, 0x80000000, 0, 0);
    }

    @Test
    @DisplayName("public key and extended-key entry points reject invalid key material")
    void rejectsInvalidExtendedKeyMaterial() {
        byte[] zero = new byte[32];
        byte[] curveOrder = HexFormat.of().parseHex(
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        byte[] validChainCode = new byte[32];

        assertThatThrownBy(() -> Bip32.privateKeyToPublicKey(zero, true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Bip32.privateKeyToPublicKey(curveOrder, false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Bip32.ExtendedKey(zero, validChainCode, null, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Bip32.ExtendedKey(
                HexFormat.of().parseHex(MASTER_PRIVATE_KEY), new byte[31], null, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
