package com.aoi;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AesCipherTest {

    private static final Logger log = LoggerFactory.getLogger(AesCipherTest.class);

    private static final AesCipher aesCipher = new AesCipher();

    /**
     * 驗證 state 的二維座標能正確映射到一維索引。
     *
     * @throws IllegalAccessException 當索引超出 state 範圍時拋出
     */
    @Test
    void idxText() throws IllegalAccessException {
        assertEquals(0, aesCipher.idx(0, 0));
        assertEquals(1, aesCipher.idx(1, 0));
        assertEquals(4, aesCipher.idx(0, 1));
    }

    /**
     * 驗證 AddRoundKey 會逐 byte 執行 XOR。
     *
     * @throws IllegalAccessException 當索引超出 state 範圍時拋出
     */
    @Test
    void addRoundKey_xorWorks() throws IllegalAccessException {
        byte[] state = new byte[16];
        byte[] key = new byte[16];

        for (int i = 0; i < 16; i++) {
            state[i] = (byte) i;
            key[i] = (byte) (15 - i);
        }

        aesCipher.addRoundKey(state, key);

        for (int i = 0; i < 16; i++) {
            assertEquals((byte) 0x0F, state[i], i + " = " + state[i]);
            log.debug(i + " = " + state[i]);
        }
    }

    /**
     * 驗證 SubBytes 會正確套用 S-Box 對應表。
     */
    @Test
    void subBytes_basicMapping() {
        byte[] state = new byte[16];
        state[0] = 0x00;
        state[1] = 0x01;
        state[2] = 0x02;

        aesCipher.subBytes(state);

        assertEquals((byte) 0x63, state[0]);
        assertEquals((byte) 0x7C, state[1]);
        assertEquals((byte) 0x77, state[2]);
    }

    /**
     * 驗證 ShiftRows 會按照 AES 規則移動各列資料。
     *
     * @throws IllegalAccessException 當索引超出 state 範圍時拋出
     */
    @Test
    void shiftRows_row() throws IllegalAccessException {
        byte[] s = new byte[16];
        for (int i = 0; i < 16; i++) s[i] = (byte) i; // 00..0F

        aesCipher.shiftRows(s);

        byte[] expected = new byte[]{
                0x00, 0x05, 0x0A, 0x0F,
                0x04, 0x09, 0x0E, 0x03,
                0x08, 0x0D, 0x02, 0x07,
                0x0C, 0x01, 0x06, 0x0B
        };

        assertArrayEquals(expected, s);
    }

    /**
     * 驗證 xtime 在 GF(2^8) 下乘以 0x02 的結果。
     */
    @Test
    void xtime() {
        // 0x57 << 1 = 0xAE, and MSB of 0x57 is 0, so no XOR 0x1B
        assertEquals(0xAE, aesCipher.xtime(0x57));
        // 0x80 << 1 = 0x100 -> low 8 bits 0x00, reduction: 0x00 ^ 0x1B = 0x1B
        assertEquals(0x1B, aesCipher.xtime(0x80));
    }

    /**
     * 驗證 GF(2^8) 乘法的已知案例、單位元與乘零行為。
     */
    @Test
    void mul() {
        //mul_knownExample AES/GF(2^8) 常見已知例：0x57 * 0x13 = 0xFE
        assertEquals(0xFE, aesCipher.mul(0x57, 0x13));

        // mul_identityAndZero
        assertEquals(0x57, aesCipher.mul(0x57, 0x01));
        assertEquals(0x00, aesCipher.mul(0x57, 0x00));

        // mul_by2_matchesXtime
        assertEquals(aesCipher.xtime(0x57), aesCipher.mul(0x57, 0x02));
    }

    /**
     * 驗證 MixColumns 對教科書常見欄向量範例的輸出。
     *
     * @throws IllegalAccessException 當索引超出 state 範圍時拋出
     */
    @Test
    void mixColumns() throws IllegalAccessException {
        byte[] s = new byte[16];

        // Input (before MixColumns)
        s[aesCipher.idx(0, 0)] = (byte) 0xD4;
        s[aesCipher.idx(0, 1)] = (byte) 0xE0;
        s[aesCipher.idx(0, 2)] = (byte) 0xB8;
        s[aesCipher.idx(0, 3)] = (byte) 0x1E;
        s[aesCipher.idx(1, 0)] = (byte) 0xBF;
        s[aesCipher.idx(1, 1)] = (byte) 0xB4;
        s[aesCipher.idx(1, 2)] = (byte) 0x41;
        s[aesCipher.idx(1, 3)] = (byte) 0x27;
        s[aesCipher.idx(2, 0)] = (byte) 0x5D;
        s[aesCipher.idx(2, 1)] = (byte) 0x52;
        s[aesCipher.idx(2, 2)] = (byte) 0x11;
        s[aesCipher.idx(2, 3)] = (byte) 0x98;
        s[aesCipher.idx(3, 0)] = (byte) 0x30;
        s[aesCipher.idx(3, 1)] = (byte) 0xAE;
        s[aesCipher.idx(3, 2)] = (byte) 0xF1;
        s[aesCipher.idx(3, 3)] = (byte) 0xE5;

        aesCipher.mixColumns(s);

        // Expected (after MixColumns)
        assertEquals((byte) 0x04, s[aesCipher.idx(0, 0)]);
        assertEquals((byte) 0xE0, s[aesCipher.idx(0, 1)]);
        assertEquals((byte) 0x48, s[aesCipher.idx(0, 2)]);
        assertEquals((byte) 0x28, s[aesCipher.idx(0, 3)]);
        assertEquals((byte) 0x66, s[aesCipher.idx(1, 0)]);
        assertEquals((byte) 0xCB, s[aesCipher.idx(1, 1)]);
        assertEquals((byte) 0xF8, s[aesCipher.idx(1, 2)]);
        assertEquals((byte) 0x06, s[aesCipher.idx(1, 3)]);
        assertEquals((byte) 0x81, s[aesCipher.idx(2, 0)]);
        assertEquals((byte) 0x19, s[aesCipher.idx(2, 1)]);
        assertEquals((byte) 0xD3, s[aesCipher.idx(2, 2)]);
        assertEquals((byte) 0x26, s[aesCipher.idx(2, 3)]);
        assertEquals((byte) 0xE5, s[aesCipher.idx(3, 0)]);
        assertEquals((byte) 0x9A, s[aesCipher.idx(3, 1)]);
        assertEquals((byte) 0x7A, s[aesCipher.idx(3, 2)]);
        assertEquals((byte) 0x4C, s[aesCipher.idx(3, 3)]);
    }

    /**
     * 驗證 encryptBlock 對 FIPS-197 標準測試向量的結果。
     *
     * @throws IllegalAccessException 當索引超出 state 範圍時拋出
     */
    @Test
    void encryptBlock_matchesFips197Vector() throws IllegalAccessException {
        byte[] key = new byte[] {
                0x2b, 0x7e, 0x15, 0x16,
                0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
                (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88,
                0x09, (byte) 0xcf, 0x4f, 0x3c
        };

        byte[] plaintext = new byte[] {
                0x32, 0x43, (byte) 0xf6, (byte) 0xa8,
                (byte) 0x88, 0x5a, 0x30, (byte) 0x8d,
                0x31, 0x31, (byte) 0x98, (byte) 0xa2,
                (byte) 0xe0, 0x37, 0x07, 0x34
        };

        byte[] expected = new byte[] {
                0x39, 0x25, (byte) 0x84, 0x1d,
                0x02, (byte) 0xdc, 0x09, (byte) 0xfb,
                (byte) 0xdc, 0x11, (byte) 0x85, (byte) 0x97,
                0x19, 0x6a, 0x0b, 0x32
        };

        byte[] actual = aesCipher.encryptBlock(plaintext, key);

        assertArrayEquals(expected, actual);
    }

}
