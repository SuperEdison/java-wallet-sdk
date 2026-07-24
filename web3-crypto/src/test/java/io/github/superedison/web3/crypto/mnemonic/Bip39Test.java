package io.github.superedison.web3.crypto.mnemonic;

import io.github.superedison.web3.crypto.wallet.UnifiedHDWallet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("BIP-39 regression tests")
class Bip39Test {

    private static final String CANONICAL_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final String UPPERCASE_MNEMONIC = CANONICAL_MNEMONIC.toUpperCase(Locale.ROOT);

    @Test
    @DisplayName("official vector keeps NFKD and PBKDF2 behavior")
    void derivesOfficialSeedVector() {
        byte[] seed = Bip39.mnemonicToSeed(CANONICAL_MNEMONIC, "TREZOR");

        assertThat(HexFormat.of().formatHex(seed)).isEqualTo(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
                        + "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    }

    @Test
    @DisplayName("seed derivation preserves the case-sensitive behavior of released versions")
    void preservesPublishedCaseSensitiveSeedDerivation() {
        byte[] uppercaseSeed = Bip39.mnemonicToSeed(UPPERCASE_MNEMONIC, "");
        byte[] lowercaseSeed = Bip39.mnemonicToSeed(CANONICAL_MNEMONIC, "");

        assertThat(HexFormat.of().formatHex(uppercaseSeed)).isEqualTo(
                "58657bf0442a28e5d755d89821346417a58a10b7df52d293432f2ebf0bb6c866"
                        + "7b609ddd406f9790b4f294213288fdad71233b62b90b4b67662e1369c70eb3ba");
        assertThat(uppercaseSeed).isNotEqualTo(lowercaseSeed);
    }

    @Test
    @DisplayName("wallet import restores uppercase mnemonics created by released versions")
    void walletImportPreservesUppercaseMnemonicSeed() {
        List<String> uppercaseWords = Arrays.asList(UPPERCASE_MNEMONIC.split(" "));
        byte[] expectedSeed = Bip39.mnemonicToSeed(UPPERCASE_MNEMONIC, "");

        try (UnifiedHDWallet wallet = UnifiedHDWallet.fromMnemonic(uppercaseWords)) {
            assertThat(wallet.getSeed()).isEqualTo(expectedSeed);
        }
    }

    @Test
    @DisplayName("case-insensitive validation and entropy recovery remain compatible")
    void recoversUppercaseMnemonicWithoutReturningWrongEntropy() {
        List<String> uppercaseWords = Arrays.asList(UPPERCASE_MNEMONIC.split(" "));

        assertThat(Bip39.validateMnemonic(UPPERCASE_MNEMONIC)).isTrue();
        assertThat(Bip39.validateMnemonic(uppercaseWords)).isTrue();
        assertThat(Bip39.mnemonicToEntropy(uppercaseWords)).containsOnly((byte) 0).hasSize(16);
    }

    @Test
    @DisplayName("canonical mnemonic round-trips to the official entropy")
    void canonicalMnemonicRoundTripsToEntropy() {
        List<String> words = Arrays.asList(CANONICAL_MNEMONIC.split(" "));

        assertThat(Bip39.validateMnemonic(words)).isTrue();
        assertThat(Bip39.mnemonicToEntropy(words)).containsOnly((byte) 0).hasSize(16);
    }

    @Test
    @DisplayName("entropy conversion accepts every standard BIP-39 entropy size")
    void acceptsStandardEntropyLengths() {
        int[] entropyLengths = {16, 20, 24, 28, 32};
        int[] expectedWordCounts = {12, 15, 18, 21, 24};

        for (int i = 0; i < entropyLengths.length; i++) {
            assertThat(Bip39.entropyToMnemonic(new byte[entropyLengths[i]]))
                    .hasSize(expectedWordCounts[i]);
        }
    }

    @Test
    @DisplayName("entropy conversion rejects sizes that would lose bits")
    void rejectsNonStandardEntropyLengths() {
        assertThatThrownBy(() -> Bip39.entropyToMnemonic(null))
                .isInstanceOf(IllegalArgumentException.class);
        for (int length : new int[]{0, 15, 17, 31, 33}) {
            assertThatThrownBy(() -> Bip39.entropyToMnemonic(new byte[length]))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("16, 20, 24, 28, or 32");
        }
    }

    @Test
    @DisplayName("validation rejects whitespace that seed derivation must preserve")
    void rejectsNonCanonicalWhitespaceWithoutChangingSeedCompatibility() {
        String leadingSpace = " " + CANONICAL_MNEMONIC;
        String trailingSpace = CANONICAL_MNEMONIC + " ";
        String doubledSpace = CANONICAL_MNEMONIC.replaceFirst(" ", "  ");
        String tabSeparated = CANONICAL_MNEMONIC.replace(' ', '\t');

        assertThat(Bip39.validateMnemonic(leadingSpace)).isFalse();
        assertThat(Bip39.validateMnemonic(trailingSpace)).isFalse();
        assertThat(Bip39.validateMnemonic(doubledSpace)).isFalse();
        assertThat(Bip39.validateMnemonic(tabSeparated)).isFalse();
        assertThat(Bip39.mnemonicToSeed(doubledSpace, ""))
                .isNotEqualTo(Bip39.mnemonicToSeed(CANONICAL_MNEMONIC, ""));
    }

    @Test
    @DisplayName("validation handles null words without throwing")
    void rejectsNullWord() {
        List<String> words = Arrays.asList(CANONICAL_MNEMONIC.split(" "));
        words.set(0, null);

        assertThat(Bip39.validateMnemonic(words)).isFalse();
    }
}
