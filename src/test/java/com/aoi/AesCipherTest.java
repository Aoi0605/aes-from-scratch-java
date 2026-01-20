package com.aoi;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AesCipherTest {

    private static final Logger log = LoggerFactory.getLogger(AesCipherTest.class);

    private static final AesCipher aesCipher = new AesCipher();

    @Test
    void idxText() throws IllegalAccessException {
        assertEquals(0, aesCipher.idx(0, 0));
        assertEquals(1, aesCipher.idx(1, 0));
        assertEquals(4, aesCipher.idx(0, 1));
    }

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

    @Test
    void shiftRows_row() throws IllegalAccessException {
        byte[] s = new byte[16];
        for (int i = 0; i < 16; i++) s[i] = (byte) i; // 00..0F

        aesCipher.shiftRows(s);

        byte[] expected = new byte[] {
                0x00, 0x05, 0x0A, 0x0F,
                0x04, 0x09, 0x0E, 0x03,
                0x08, 0x0D, 0x02, 0x07,
                0x0C, 0x01, 0x06, 0x0B
        };

        assertArrayEquals(expected, s);
    }

    @Test
    void xtime() {
        // 0x57 << 1 = 0xAE, and MSB of 0x57 is 0, so no XOR 0x1B
        assertEquals(0xAE, aesCipher.xtime(0x57));
        // 0x80 << 1 = 0x100 -> low 8 bits 0x00, reduction: 0x00 ^ 0x1B = 0x1B
        assertEquals(0x1B, aesCipher.xtime(0x80));
    }
}
