# Encrypt something in Java and decrypt it in JavaScript by example

## Encrypt String in Java

### Before use the cipher

When you use the code like below,

```java
Cipher cipher = Cipher.getInstance("AES");
```

you must know the default transformation of cipher, in this case, the defaults for AES is `AES/ECB/PKCS5Padding`

### Let's encript it

#### Sample Java Code
```java
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
```

#### Code Output
```
THIS KEY WILL BE USED FOR JS-SIDE = QUJDREVGR0hJSktMTU5PUA==

PLAIN = 안녕하세요
ENCRYPTED = +KLDqBupgl+Cus1QMBtBpQ==
```

Code `QUJDREVGR0hJSktMTU5PUA==` will use in next section.

## Decrypt string in JavaScript

In this example, we use the library [CryptoJS](https://github.com/brix/crypto-js) to decrypt encrypted string

## Before use the cipher library
- [From the document](http://cryptojs.altervista.org/secretkey/doc/doc_aes_cryptojs-v3.html), AES of CryptoJS uses the mode of operation `CBC` with `PKCS#7` padding as the default.
- In the Java-side, by the way, the defaults for AES uses `ECB` with `PKCS#5` padding as the default.

If you want to use the CryptoJS, you should change the defaults as the same as the Java-side does.

### Sample JavaScript Code
[See the code below](index.js) or [Run sample page](https://jsfiddle.net/kyungw00k/1j6jojkg/)

```js
var CryptoJS = require('crypto-js')

var base64EncodedKeyFromJava = 'QUJDREVGR0hJSktMTU5PUA=='; /* copied from output of Java program  */
var keyForCryptoJS = CryptoJS.enc.Base64.parse(base64EncodedKeyFromJava);

var encryptString = "+KLDqBupgl+Cus1QMBtBpQ==" /* will be decrypted to '안녕하세요' */
var decodeBase64 = CryptoJS.enc.Base64.parse(encryptString)

var decryptedData = CryptoJS.AES.decrypt(
  {
    ciphertext: decodeBase64
  },
  keyForCryptoJS,
  {
    mode: CryptoJS.mode.ECB /* Override the defaults */
    /*padding: CryptoJS.pad.Pkcs7 *//* PKCS#5 is a subset of PKCS#7, and */
  }
);

var decryptedText = decryptedData.toString(CryptoJS.enc.Utf8);

console.log( `decryptedText = '${new String(decryptedText)}'`);
```

## References
- [Default transformations for AES, DES, DESede (Triple DES) in Java](http://ykchee.blogspot.kr/2012/09/default-transformations-for-aes-des.html)
- [What is the difference between PKCS#5 padding and PKCS#7 padding](http://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding)
