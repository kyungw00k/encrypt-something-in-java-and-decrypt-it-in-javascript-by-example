import org.apache.commons.net.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;

public class EncryptUtil {

    public static final byte[] KEY = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P'};

    private static Cipher ecipher;
    private static Cipher dcipher;

    static {
        try {
            ecipher = Cipher.getInstance("AES");
            SecretKeySpec eSpec = new SecretKeySpec(KEY, "AES");
            ecipher.init(Cipher.ENCRYPT_MODE, eSpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


        try {
            dcipher = Cipher.getInstance("AES");
            SecretKeySpec dSpec = new SecretKeySpec(KEY, "AES");
            dcipher.init(Cipher.DECRYPT_MODE, dSpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encrypt(String value) {
        byte[] b1 = value.getBytes();
        byte[] encryptedValue;
        try {
            encryptedValue = ecipher.doFinal(b1);
            return Base64.encodeBase64String(encryptedValue);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * USE THIS FEATURE IN JAVASCRIPT-SIDE
     */
    /*
    public static String decrypt(String encryptedValue) {
        byte[] decryptedValue = Base64.decodeBase64(encryptedValue.getBytes());
        byte[] decValue;
        try {
            decValue = dcipher.doFinal(decryptedValue);
            return new String(decValue);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }
     */

    public static void main(String args[]) throws IOException {
        String keyForJS = Base64.encodeBase64String(KEY);
        System.out.println("THIS KEY WILL BE USED FOR JS-SIDE = " + keyForJS);

        String plainText = "안녕하세요";
        System.out.println("PLAIN = " + plainText);
        System.out.println("ENCRYPTED = " + EncryptUtil.encrypt("안녕하세요"));
    }
}
