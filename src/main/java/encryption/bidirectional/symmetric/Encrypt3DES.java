package encryption.bidirectional.symmetric;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * 双向对称3DES算法
 */
public class Encrypt3DES {
    private KeyGenerator keyGenerator;
    private SecretKey secretKey;
    private Cipher cipher;
    private byte[] cipherByte;

    public Encrypt3DES() throws NoSuchAlgorithmException, NoSuchPaddingException {
        Security.addProvider(new com.sun.crypto.provider.SunJCE());
        keyGenerator = KeyGenerator.getInstance("DESede");
        secretKey = keyGenerator.generateKey();
        cipher = Cipher.getInstance("DESede");
    }

    public byte[] encrypt(String data) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] src = data.getBytes();
        cipherByte = cipher.doFinal(src);
        return cipherByte;
    }

    public byte[] decrypt(byte[] bytes) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        cipherByte = cipher.doFinal(bytes);
        return cipherByte;
    }
}
