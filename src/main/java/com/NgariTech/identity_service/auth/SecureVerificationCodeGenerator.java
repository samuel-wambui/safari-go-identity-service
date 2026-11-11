package com.NgariTech.identity_service.auth;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class SecureVerificationCodeGenerator implements VerificationCodeGenerator {

    private static final char[] DIGITS = "0123456789".toCharArray();
    private static final char[] UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static final char[] LOWERCASE = "abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final char[] ALL = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();
    private static final int CODE_LENGTH = 6;

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generate() {
        char[] code = new char[CODE_LENGTH];
        code[0] = randomFrom(DIGITS);
        code[1] = randomFrom(UPPERCASE);
        code[2] = randomFrom(LOWERCASE);

        for (int index = 3; index < code.length; index++) {
            code[index] = randomFrom(ALL);
        }

        shuffle(code);
        return new String(code);
    }

    private char randomFrom(char[] values) {
        return values[secureRandom.nextInt(values.length)];
    }

    private void shuffle(char[] code) {
        for (int index = code.length - 1; index > 0; index--) {
            int swapIndex = secureRandom.nextInt(index + 1);
            char current = code[index];
            code[index] = code[swapIndex];
            code[swapIndex] = current;
        }
    }
}
