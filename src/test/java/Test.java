import encryption.bidirectional.asymmetric.EncryptRSA;
import encryption.bidirectional.symmetric.Encrypt3DES;
import encryption.bidirectional.symmetric.EncryptAES;
import encryption.bidirectional.symmetric.EncryptDES;
import encryption.oneway.EncryptMD5;
import encryption.oneway.EncryptSHA;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Test {
    private static final String LOG_IDENTIFIER = "------------------------------";

    @org.junit.Test
    public void testDES() throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        EncryptDES encryptDES = new EncryptDES();
        String data = "你好，我的爱人，我对你的爱仍在！";
        System.out.println(LOG_IDENTIFIER + "原始数据:" + data);
        byte[] encrytedDataBytes = encryptDES.encrypt(data);
        byte[] decrytedDataBytes = encryptDES.decrypt(encrytedDataBytes);
        System.out.println(LOG_IDENTIFIER + "DES加密后的data:" + new String(encrytedDataBytes));
        System.out.println(LOG_IDENTIFIER + "DES解密后的data:" + new String(decrytedDataBytes));
    }

    @org.junit.Test
    public void testDES3() throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Encrypt3DES encrypt3DES = new Encrypt3DES();
        String data = "你好，我的爱人，我对你的爱仍在！";
        System.out.println(LOG_IDENTIFIER + "原始数据:" + data);
        byte[] encrytedDataBytes = encrypt3DES.encrypt(data);
        byte[] decrytedDataBytes = encrypt3DES.decrypt(encrytedDataBytes);
        System.out.println(LOG_IDENTIFIER + "3DES加密后的data:" + new String(encrytedDataBytes));
        System.out.println(LOG_IDENTIFIER + "3DES解密后的data:" + new String(decrytedDataBytes));
    }

    @org.junit.Test
    public void testAES() throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        EncryptAES encryptAES = new EncryptAES();
        String data = "你好，我的爱人，我对你的爱仍在！";
        System.out.println(LOG_IDENTIFIER + "原始数据:" + data);
        byte[] encrytedDataBytes = encryptAES.encrypt(data);
        byte[] decrytedDataBytes = encryptAES.decrypt(encrytedDataBytes);
        System.out.println(LOG_IDENTIFIER + "AES加密后的data:" + new String(encrytedDataBytes));
        System.out.println(LOG_IDENTIFIER + "AES解密后的data:" + new String(decrytedDataBytes));
    }

    @org.junit.Test
    public void testRSA() throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        EncryptRSA encryptRSA = new EncryptRSA();
        String data = "你好，我的爱人，我对你的爱仍在！";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        System.out.println(LOG_IDENTIFIER + "原始数据:" + data);
        byte[] encrytedDataBytes = encryptRSA.encrypt(publicKey, data.getBytes());
        byte[] decrytedDataBytes = encryptRSA.decrypt(privateKey, encrytedDataBytes);
        System.out.println(LOG_IDENTIFIER + "AES加密后的data:" + new String(encrytedDataBytes));
        System.out.println(LOG_IDENTIFIER + "AES解密后的data:" + new String(decrytedDataBytes));
    }

    @org.junit.Test
    public void testMD5() throws NoSuchAlgorithmException {
        EncryptMD5 encryptMD5 = new EncryptMD5();
        String data = "我爱你，我的那个她！";
        System.out.println(LOG_IDENTIFIER + "原始数据:" + data);
        System.out.println(LOG_IDENTIFIER + "MD5加密后的data:" + new String(encryptMD5.encrypt(data)));
    }

    @org.junit.Test
    public void testSHA() throws NoSuchAlgorithmException {
        EncryptSHA encryptSHA = new EncryptSHA();
        String data = "我爱你，我的那个她！";
        System.out.println(LOG_IDENTIFIER + "原始数据:" + data);
        System.out.println(LOG_IDENTIFIER + "MD5加密后的data:" + new String(encryptSHA.encrypt(data)));
    }
}
