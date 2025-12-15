package io.github.superedison.web3.crypto.mnemonic;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * BIP-39 词表加载器
 */
public final class Bip39WordList {

    public static final String[] ENGLISH = loadWordList("english");

    private Bip39WordList() {}

    private static String[] loadWordList(String language) {
        String resourcePath = "/bip-39/" + language + ".txt";
        try (InputStream is = Bip39WordList.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new RuntimeException("Word list not found: " + resourcePath);
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            List<String> words = new ArrayList<>(2048);
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    words.add(line);
                }
            }
            if (words.size() != 2048) {
                throw new RuntimeException("Invalid word list size: " + words.size());
            }
            return words.toArray(new String[0]);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load word list: " + language, e);
        }
    }
}