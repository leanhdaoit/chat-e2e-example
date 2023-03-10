const { ec } = require("elliptic");
const curve = new ec("p256");
const { Crypto } = require("@peculiar/webcrypto");
const { webcrypto } = require("crypto");

exports.importKeyByPeculiarWebcrypto = async (privateKeyHex) => {
  const crypto = new Crypto();
  const keyPair = curve.keyFromPrivate(privateKeyHex);
  const privateKeyBN = keyPair.getPrivate();
  const publicKeyBasePoint = keyPair.getPublic();
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: publicKeyBasePoint.getX().toBuffer().toString("base64url"),
    y: publicKeyBasePoint.getY().toBuffer().toString("base64url"),
    d: privateKeyBN.toBuffer().toString("base64url"),
  };
  const privateKey = await crypto.subtle
    .importKey(
      "jwk",
      jwk,
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      ["deriveKey"]
    )
    .then((privateKey) => privateKey)
    .catch((error) => console.log("error: " + error));
  console.log("===========Import key by old @peculiar/webcrypto=============");
  console.log("jwk: " + JSON.stringify(jwk));
  console.log("privateKey:" + privateKey);
  return privateKey;
};

exports.importKeyByOldWebcrypto = async (privateKeyHex) => {
  const keyPair = curve.keyFromPrivate(privateKeyHex);
  const privateKeyBN = keyPair.getPrivate();
  const publicKeyBasePoint = keyPair.getPublic();
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: publicKeyBasePoint.getX().toBuffer().toString("base64url"),
    y: publicKeyBasePoint.getY().toBuffer().toString("base64url"),
    d: privateKeyBN.toBuffer().toString("base64url"),
  };
  const privateKey = await webcrypto.subtle
    .importKey(
      "jwk",
      jwk,
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      ["deriveKey"]
    )
    .then((privateKey) => privateKey)
    .catch((error) => console.log("error: " + error));
  console.log("===========Import key by old webcrypto=============");
  console.log("jwk: " + JSON.stringify(jwk));
  console.log("privateKey:" + privateKey);
  return privateKey;
};

(async () => {
  const privateKeyAlice = "03ecc060e7fc29863166f3fa6a490be9236304fca0b2d0bb5402cfd9cba1d100";
  await this.importKeyByPeculiarWebcrypto(privateKeyAlice);
  await this.importKeyByOldWebcrypto(privateKeyAlice);
})();
