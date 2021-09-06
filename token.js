import {
  base64ToString,
  convertToBase64,
  removeEqualsChar,
  shaHashWithSecret,
} from "./utils.js";
import { headerInfo, secret } from "./constant.js";

export const sign = (data, secret, seconds) => {
  if (!secret) throw new Error("secret not provided");
  const header = convertToBase64(headerInfo);
  const currentDate = new Date();
  const updatedData = {
    ...data,
    iat: currentDate.getTime(),
  };
  if (seconds) {
    updatedData.exp = currentDate.getTime() + seconds * 1000;
  }
  const payload = convertToBase64(updatedData);
  const tokenWithoutSignature = `${removeEqualsChar(header)}.${removeEqualsChar(
    payload
  )}`;
  const hash = shaHashWithSecret(tokenWithoutSignature, secret);
  const token = `${tokenWithoutSignature}.${hash}`;
  console.log(token);
  return token;
};

export const verify = (data, secret) => {
  if (!secret) throw new Error("secret not provided");
  const [header, payload, signature] = data?.split(".");
  const tokenWithoutSignature = `${removeEqualsChar(header)}.${removeEqualsChar(
    payload
  )}`;
  const hash = shaHashWithSecret(tokenWithoutSignature, secret);
  if (hash !== signature) throw new Error("Invalid token");
  const decodedData = JSON.parse(base64ToString(payload));
  if (decodedData.exp) {
    const currentTime = new Date().getTime();
    if (currentTime > decodedData.exp) throw new Error("Token expired");
  }
  return decodedData;
};
