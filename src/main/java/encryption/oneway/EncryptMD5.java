package encryption.oneway;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 单向加密（信息摘要)MD5
 */
public class EncryptMD5 {

    public byte[] encrypt(String data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] srcBytes = data.getBytes();
        messageDigest.update(srcBytes);
        return messageDigest.digest();
    }

}
