package encryption.bidirectional.symmetric;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * 双向对称加密DES算法
 */
public class EncryptDES {
    private KeyGenerator keyGenerator;
    private SecretKey secretKey;
    private Cipher cipher;
    private byte[] cipherByte;

    public EncryptDES() throws NoSuchAlgorithmException, NoSuchPaddingException {
        Security.addProvider(new com.sun.crypto.provider.SunJCE());
        keyGenerator = KeyGenerator.getInstance("DES");
        secretKey = keyGenerator.generateKey();
        cipher = Cipher.getInstance("DES");
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
