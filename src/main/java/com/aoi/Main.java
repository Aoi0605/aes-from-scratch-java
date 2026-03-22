package com.aoi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    /**
     * 執行 AES-128 單區塊加密的整體 smoke test。
     *
     * <p>此進入點會使用 FIPS-197 的標準測試向量進行加密，並輸出金鑰、明文、
     * 預期密文、實際密文與比對結果，方便快速確認整體流程是否正確。</p>
     *
     * @param args 啟動程式時帶入的命令列參數，目前未使用
     * @throws IllegalAccessException 當 AES state 索引計算超出 4x4 範圍時拋出
     */
    public static void main(String[] args) throws IllegalAccessException {
        AesCipher aesCipher = new AesCipher();

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

        byte[] expectedCiphertext = new byte[] {
                0x39, 0x25, (byte) 0x84, 0x1d,
                0x02, (byte) 0xdc, 0x09, (byte) 0xfb,
                (byte) 0xdc, 0x11, (byte) 0x85, (byte) 0x97,
                0x19, 0x6a, 0x0b, 0x32
        };

        byte[] actualCiphertext = aesCipher.encryptBlock(plaintext, key);

        log.info("key      = {}", toHex(key));
        log.info("plain    = {}", toHex(plaintext));
        log.info("expected = {}", toHex(expectedCiphertext));
        log.info("actual   = {}", toHex(actualCiphertext));
        log.info("match    = {}", java.util.Arrays.equals(expectedCiphertext, actualCiphertext));
    }

    /**
     * 將 byte 陣列轉成連續的小寫十六進位字串。
     *
     * @param data 要轉換的 byte 陣列
     * @return 不含空白與前綴的十六進位字串
     */
    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
