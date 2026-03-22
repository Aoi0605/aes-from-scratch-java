package com.aoi;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AesKeyScheduleTest {

    private final AesKeySchedule ks = new AesKeySchedule();

    /**
     * 驗證 word 會以 big-endian 將 4 個 byte 打包成 int。
     */
    @Test
    void word() {
        // packsBigEndian_basic
        byte[] a = new byte[] { 0x2b, 0x7e, 0x15, 0x16 };
        assertEquals(0x2b7e1516, ks.word(a, 0));

        // handlesSignedBytes_correctly
        byte[] b = new byte[] { (byte) 0xAB, (byte) 0xF7, 0x15, (byte) 0x88 };
        assertEquals(0xABF71588, ks.word(b, 0));
    }

    /**
     * 驗證 rotWord 會把 word 以 byte 為單位循環左移。
     */
    @Test
    void rotWord() {
        assertEquals(0xCF4F3C09, ks.rotWord(0x09CF4F3C));
    }

    /**
     * 驗證 subWord 會對每個 byte 套用 S-Box。
     */
    @Test
    void subWord_appliesSboxPerByte() {
        // 教科書常用對拍：SubWord(0xCF4F3C09) = 0x8A84EB01
        assertEquals(0x8A84EB01, ks.subWord(0xCF4F3C09));
    }

    /**
     * 驗證手動推導到 w8 的 key schedule 結果與已知向量一致。
     */
    @Test
    void keyExpansion_w8_matchesVector() {
        byte[] key = new byte[] {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c
        };

        int w0 = ks.word(key, 0);
        int w1 = ks.word(key, 4);
        int w2 = ks.word(key, 8);
        int w3 = ks.word(key, 12);

        int w4 = w0 ^ ks.g(w3, 1);
        int w5 = w1 ^ w4;
        int w6 = w2 ^ w5;
        int w7 = w3 ^ w6;

        int g2 = ks.g(w7, 2);
        assertEquals(0x52386BE5, g2);

        int w8 = w4 ^ g2;
        assertEquals(0xF2C295F2, w8);
    }

    /**
     * 驗證 keyExpansion 至少前幾個已知 words 與標準向量一致。
     */
    @Test
    void keyExpansion_matchesKnownVector_prefix() {
        byte[] key = new byte[] {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c
        };

        int[] w = ks.keyExpansion(key);

        assertEquals(44, w.length);

        assertEquals(0x2b7e1516, w[0]);
        assertEquals(0x28aed2a6, w[1]);
        assertEquals(0xabf71588, w[2]);
        assertEquals(0x09cf4f3c, w[3]);

        assertEquals(0xa0fafe17, w[4]);
        assertEquals(0xf2c295f2, w[8]);
    }

    /**
     * 驗證 roundKey 能正確取出指定回合的 16-byte 金鑰。
     */
    @Test
    void roundKey() {
        byte[] key = new byte[] {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c
        };

        int[] expanded = ks.keyExpansion(key);
        byte[] round0 = ks.roundKey(expanded, 0);

        assertArrayEquals(key, round0);

        byte[] key1 = new byte[] {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c
        };

        int[] expanded1 = ks.keyExpansion(key1);
        byte[] round1 = ks.roundKey(expanded1, 1);

        byte[] expected = new byte[] {
                (byte) 0xa0, (byte) 0xfa, (byte) 0xfe, 0x17,
                (byte) 0x88, 0x54, 0x2c, (byte) 0xb1,
                0x23, (byte) 0xa3, 0x39, 0x39,
                0x2a, 0x6c, 0x76, 0x05
        };

        assertArrayEquals(expected, round1);
    }
}
