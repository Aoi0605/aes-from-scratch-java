package com.aoi;

public class AesKeySchedule {

    /**
     * 將輸入陣列中的 4 個 byte 依 big-endian 打包成一個 32-bit word。
     *
     * @param in 來源 byte 陣列
     * @param off 起始偏移量
     * @return 打包後的 32-bit word
     */
    int word(byte[] in, int off) {

        int b0 = in[off] & 0xFF;
        int b1 = in[off + 1] & 0xFF;
        int b2 = in[off + 2] & 0xFF;
        int b3 = in[off + 3] & 0xFF;

        // int 最多存 32 bit
        int w0 = b0 << 24;
        int w1 = b1 << 16;
        int w2 = b2 << 8;
        int w3 = b3;

        int word = w0 | w1 | w2 | w3;

        return word;
    }

    /**
     * 將 32-bit word 以 byte 為單位循環左移 1 格。
     *
     * @param word 要旋轉的 32-bit word
     * @return 旋轉後的 32-bit word
     */
    int rotWord(int word) {
        // 拆出四個 byte（以 big-endian 視角：b0 是最高位）
        int b0 = (word >>> 24) & 0xFF;
        int b1 = (word >>> 16) & 0xFF;
        int b2 = (word >>> 8) & 0xFF;
        int b3 = word & 0xFF;

        // 循環左旋 1 byte: [b0 b1 b2 b3] -> [b1 b2 b3 b0]
        int nb0 = b1;
        int nb1 = b2;
        int nb2 = b3;
        int nb3 = b0;

        // 組回 32-bit word
        int w0 = (nb0 << 24);
        int w1 = (nb1 << 16);
        int w2 = (nb2 << 8);
        int w3 = nb3;

        return w0 | w1 | w2 | w3;
    }

    /**
     * 對一個 32-bit word 的每個 byte 套用 AES S-Box。
     *
     * @param word 要替換的 32-bit word
     * @return 套用 S-Box 後的新 word
     */
    int subWord(int word) {
        // 將word拆出4個bite
        int b0 = (word >>> 24) & 0xFF;
        int b1 = (word >>> 16) & 0xFF;
        int b2 = (word >>> 8) & 0xFF;
        int b3 = word & 0xFF;

        //將4個byte走一遍S-box
        int sb0 = AesTables.SBOX[b0];
        int sb1 = AesTables.SBOX[b1];
        int sb2 = AesTables.SBOX[b2];
        int sb3 = AesTables.SBOX[b3];

        //走完後組回32-bit word
        int w0 = sb0 << 24;
        int w1 = sb1 << 16;
        int w2 = sb2 << 8;
        int w3 = sb3;

        return w0 | w1 | w2 | w3;
    }

    /**
     * 執行 AES key schedule 的 g 函數。
     *
     * <p>此步驟會先做 RotWord，再做 SubWord，最後與對應輪次的 Rcon 常數 XOR。</p>
     *
     * @param w 輸入 word
     * @param r 輪次，AES-128 需落在 1..10
     * @return 套用 g 函數後的 word
     */
    int g(int w, int r) {
        int rw = rotWord(w);
        int sw = subWord(rw);
        int out = sw ^ AesTables.RCON[r];
        return out;
    }

    /**
     * 將 16-byte AES-128 金鑰展開成 44 個 32-bit words。
     *
     * @param key16 原始 16-byte 金鑰
     * @return 長度為 44 的 expanded key words
     */
    int[] keyExpansion(byte[] key16) {
        if (key16 == null || key16.length != 16) {
            throw new IllegalArgumentException("AES-128 key must be 16 bytes");
        }

        int[] w = new int[44];

        // 前 4 個 word 直接來自原始 key
        w[0] = word(key16, 0);
        w[1] = word(key16, 4);
        w[2] = word(key16, 8);
        w[3] = word(key16, 12);

        // 從 w[4] 推到 w[43]
        for (int i = 4; i < 44; i++) {
            int temp = w[i - 1];

            if (i % 4 == 0) {
                temp = g(temp, i / 4);
            }

            w[i] = w[i - 4] ^ temp;
        }

        return w;
    }

    /**
     * 從 expanded key 中取出指定回合的 16-byte round key。
     *
     * @param expandedKey 長度為 44 的 AES-128 expanded key
     * @param round 回合編號，範圍為 0..10
     * @return 指定回合的 16-byte round key
     */
    byte[] roundKey(int[] expandedKey, int round) {
        if (expandedKey == null || expandedKey.length != 44) {
            throw new IllegalArgumentException("expandedKey must contain 44 words for AES-128");
        }
        if (round < 0 || round > 10) {
            throw new IllegalArgumentException("round must be in 0..10");
        }

        byte[] roundKey16 = new byte[16];
        int base = round * 4;

        for (int i = 0; i < 4; i++) {
            int w = expandedKey[base + i];

            roundKey16[i * 4] = (byte) ((w >>> 24) & 0xFF);
            roundKey16[i * 4 + 1] = (byte) ((w >>> 16) & 0xFF);
            roundKey16[i * 4 + 2] = (byte) ((w >>> 8) & 0xFF);
            roundKey16[i * 4 + 3] = (byte) (w & 0xFF);
        }

        return roundKey16;
    }
}
