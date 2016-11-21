## Decrypt String using AES(CryptoJS) from JS

Use [CryptoJS](https://github.com/brix/crypto-js) to decrypt encrypted string

[From the document](http://cryptojs.altervista.org/secretkey/doc/doc_aes_cryptojs-v3.html), AES of CryptoJS uses the mode of operation `CBC` with `PKCS#7` padding as the default.

In the Java-side, by the way, the defaults for AES uses `ECB` with `PKCS#5` padding as the default.

If you want to use the CryptoJS, you should change the defaults as the same as the Java-side does.

### Example
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
- [What is the difference between PKCS#5 padding and PKCS#7 padding](http://crypto.stackexchange.com/questions/9043/what-is-the-difference-between-pkcs5-padding-and-pkcs7-padding)
