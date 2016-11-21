var CryptoJS = require('crypto-js')

var base64EncodedKeyFromJava = 'QUJDREVGR0hJSktMTU5PUA==';
var keyForCryptoJS = CryptoJS.enc.Base64.parse(base64EncodedKeyFromJava);

var encryptString = "+KLDqBupgl+Cus1QMBtBpQ=="
var decodeBase64 = CryptoJS.enc.Base64.parse(encryptString)

var decryptedData = CryptoJS.AES.decrypt(
  {
    ciphertext: decodeBase64
  },
  keyForCryptoJS,
  {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  }
);

var decryptedText = decryptedData.toString(CryptoJS.enc.Utf8);

console.log( `decryptedText = '${new String(decryptedText)}'`);
