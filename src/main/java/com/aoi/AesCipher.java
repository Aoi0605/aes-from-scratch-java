package com.aoi;

public class AesCipher {

    /**
     * 使用 AES-128 對單一 16-byte 區塊進行加密。
     *
     * <p>流程包含初始 AddRoundKey、9 輪標準回合，以及最後一輪不含 MixColumns 的收尾回合。</p>
     *
     * @param plaintext16 要加密的 16-byte 明文區塊
     * @param key16 AES-128 使用的 16-byte 金鑰
     * @return 加密後的 16-byte 密文區塊
     * @throws IllegalAccessException 當內部 state 索引計算超出 4x4 範圍時拋出
     */
    byte[] encryptBlock(byte[] plaintext16, byte[] key16) throws IllegalAccessException {
        if (plaintext16 == null || plaintext16.length != 16) {
            throw new IllegalArgumentException("plaintext must be 16 bytes");
        }
        if (key16 == null || key16.length != 16) {
            throw new IllegalArgumentException("AES-128 key must be 16 bytes");
        }

        AesKeySchedule keySchedule = new AesKeySchedule();
        int[] expandedKey = keySchedule.keyExpansion(key16);

        byte[] state = plaintext16.clone();

        // Initial round
        addRoundKey(state, keySchedule.roundKey(expandedKey, 0));

        // Rounds 1..9
        for (int round = 1; round <= 9; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, keySchedule.roundKey(expandedKey, round));
        }

        // Final round (no MixColumns)
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, keySchedule.roundKey(expandedKey, 10));

        return state;
    }

    /**
     * 將 AES 的 state 二維座標轉成一維陣列索引。
     *
     * <p>state[row][col] 對應到扁平的 flat[4 * col + row]，採用 AES 慣用的 column-major 排列：</p>
     *
     * <pre>
     * 0 4 8  12
     * 1 5 9  13
     * 2 6 10 14
     * 3 7 11 15
     * </pre>
     *
     * @param row state 的列索引，範圍必須是 0..3
     * @param col state 的欄索引，範圍必須是 0..3
     * @return 對應的一維陣列索引
     * @throws IllegalAccessException 當 row 或 col 超出 0..3 範圍時拋出
     */
    int idx(int row, int col) throws IllegalAccessException {
        if (row < 0 || row > 3 || col < 0 || col > 3) {
            throw  new IllegalAccessException("row/col must be in 0..3");
        }

        return 4 * col + row;
    }

    /**
     * 將目前回合金鑰 XOR 到 state 上。
     *
     * @param state16 長度為 16 的 state 陣列
     * @param roundKey16 長度為 16 的回合金鑰
     */
    void addRoundKey(byte[] state16, byte[] roundKey16) {
        for (int i = 0; i < 16; i++) {
            //(byte) 轉型是因為 Java 的 ^ 會把 byte 升格成 int 運算，最後要塞回 byte。
            state16[i] = (byte) (state16[i] ^ roundKey16[i]);
        }
    }

    /**
     * 對 state 的每個 byte 套用 AES S-Box 取代。
     *
     * @param state16 長度為 16 的 state 陣列
     */
    void subBytes(byte[] state16) {
        for (int i = 0; i < 16; i++) {
            int x = state16[i] & 0xFF;

            //寫 state16[i] 時，即使該 byte 在記憶體裡是 0x80（二進位 1000_0000），Java 讀成 byte 會是 -128。
            //如果你直接拿它當索引：SBOX[state16[i]]，那就是 SBOX[-128]，立刻爆掉（負索引）。
            state16[i] = (byte) AesTables.sbox(x);
        }
    }

    /**
     * 對 state 執行 AES 的 ShiftRows 步驟。
     *
     * <p>第 0 列不動，第 1 列左移 1，第 2 列左移 2，第 3 列左移 3。</p>
     *
     * @param state16 長度為 16 的 state 陣列
     * @throws IllegalAccessException 當內部 state 索引計算超出 4x4 範圍時拋出
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

    /**
     * 計算 AES 有限體中的乘以 x，也就是乘以 0x02。
     *
     * @param x 要運算的單一 byte 值，實際只取低 8 位
     * @return 在 GF(2^8) 下乘以 0x02 的結果
     */
    int xtime(int x) {
        x &= 0xFF;
        int shifted = x << 1; //：GF(2) 的左移（多項式乘 x）
        if((x & 0x80) != 0) { //如果原本最高位是 1，左移後需要 reduction
            shifted ^= 0x1B; //對應模多項式化簡（AES 固定常數）
        }
        return shifted & 0xFF;
    }

    /**
     * 在 AES 使用的 GF(2^8) 有限體中執行乘法。
     *
     * @param a 左操作數，實際只取低 8 位
     * @param b 右操作數，實際只取低 8 位
     * @return 乘法結果，範圍為 0..255
     */
    int mul(int a, int b) {

        //保證輸入在 0..255（避免 Java signed/高位污染）
        a &= 0xFF;
        b &= 0xFF;

        int res = 0;
        for(int i = 0; i < 8; i++) {
            if((b & 1) != 0){
                res ^= a; //GF 加法 = XOR
            }
            a = xtime(a); //GF 乘以 2（含 0x1B 化簡）
            b >>>= 1; // unsigned shift 輸出壓回 8-bit
        }

        return res & 0xFF;
    }

    /**
     * 對 state 的每一個欄執行 AES 的 MixColumns 步驟。
     *
     * @param state16 長度為 16 的 state 陣列
     * @throws IllegalAccessException 當內部 state 索引計算超出 4x4 範圍時拋出
     */
    void mixColumns(byte[] state16) throws IllegalAccessException {

        byte[] temp = state16.clone();

        for (int c = 0; c < 4; c++){
            int a0 = temp[idx(0, c)] & 0xFF;
            int a1 = temp[idx(1, c)] & 0xFF;
            int a2 = temp[idx(2, c)] & 0xFF;
            int a3 = temp[idx(3, c)] & 0xFF;

            int b0 = mul(a0, 0x02) ^ mul(a1, 0x03) ^ a2 ^ a3;
            int b1 = a0 ^ mul(a1, 0x02) ^ mul(a2, 0x03) ^ a3;
            int b2 = a0 ^ a1 ^ mul(a2, 0x02) ^ mul(a3, 0x03);
            int b3 = mul(a0, 0x03) ^ a1 ^ a2 ^ mul(a3, 0x02);

            state16[idx(0, c)] = (byte) b0;
            state16[idx(1, c)] = (byte) b1;
            state16[idx(2, c)] = (byte) b2;
            state16[idx(3, c)] = (byte) b3;
        }
    }
}
