package encryption.oneway;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 单向加密SHA
 */
public class EncryptSHA {

    public byte[] encrypt(String data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA");
        byte[] srcBytes = data.getBytes();
        messageDigest.update(srcBytes);
        return messageDigest.digest();
    }
}
