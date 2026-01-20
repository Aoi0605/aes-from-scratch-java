package com.aoi;

public class AesCipher {

    /**
     * state[row][col] 對應到扁平的 flat[4*col + row] [1,2,3 ..., 15]
     * 0 4 8  12
     * 1 5 9  13
     * 2 6 10 14
     * 3 7 11 15
     * @param row
     * @param col
     * @return
     * @throws IllegalAccessException
     */
    int idx(int row, int col) throws IllegalAccessException {
        if (row < 0 || row > 3 || col < 0 || col > 3) {
            throw  new IllegalAccessException("row/col must be in 0..3");
        }

        return 4 * col + row;
    }

    void addRoundKey(byte[] state16, byte[] roundKey16) {
        for (int i = 0; i < 16; i++) {
            //(byte) 轉型是因為 Java 的 ^ 會把 byte 升格成 int 運算，最後要塞回 byte。
            state16[i] = (byte) (state16[i] ^ roundKey16[i]);
        }
    }

    void subBytes(byte[] state16) {
        for (int i = 0; i < 16; i++) {
            int x = state16[i] & 0xFF;

            //寫 state16[i] 時，即使該 byte 在記憶體裡是 0x80（二進位 1000_0000），Java 讀成 byte 會是 -128。
            //如果你直接拿它當索引：SBOX[state16[i]]，那就是 SBOX[-128]，立刻爆掉（負索引）。
            state16[i] = (byte) AesTables.sbox(x);
        }
    }

    /**
     * Row1：左移 1 (1,0) <- (1,1) <- (1,2) <- (1,3) <- (1,0)
     * Row2：左移 2 (2,0) <- (2,2), (2,1) <- (2,3), (2,2) <- (2,0), (2,3) <- (2,1)
     * Row3：左移 3 等同右移 1：(3,0) <- (3,3), (3,1) <- (3,0), (3,2) <- (3,1), (3,3) <- (3,2)
     * @param state16
     */
    void shiftRows(byte[] state16) throws IllegalAccessException {
        byte[] temp = state16.clone();
        // row0 維持不變

        // row1 shift left 1
        state16[idx(1, 0)] = temp[idx(1, 1)];
        state16[idx(1, 1)] = temp[idx(1, 2)];
        state16[idx(1, 2)] = temp[idx(1, 3)];
        state16[idx(1, 3)] = temp[idx(1, 0)];
        // row2 shift left 2
        state16[idx(2, 0)] = temp[idx(2, 2)];
        state16[idx(2, 1)] = temp[idx(2, 3)];
        state16[idx(2, 2)] = temp[idx(2, 0)];
        state16[idx(2, 3)] = temp[idx(2, 1)];
        // row3 shift left 3
        state16[idx(3, 0)] = temp[idx(3, 3)];
        state16[idx(3, 1)] = temp[idx(3, 0)];
        state16[idx(3, 2)] = temp[idx(3, 1)];
        state16[idx(3, 3)] = temp[idx(3, 2)];
    }

    int xtime(int x) {
        x &= 0xFF;
        int shifted = x << 1;
        if((x & 0x80) != 0) {
            shifted ^= 0x1B;
        }
        return shifted & 0xFF;
    }
}
