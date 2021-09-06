import crypto from "crypto";

export const convertToBase64 = (str) => {
  return Buffer.from(JSON.stringify(str)).toString("base64");
};
export const base64ToString = (data) => {
  return Buffer.from(data, "base64").toString("ascii");
};
export const removeEqualsChar = (str) => str.replace(/=/g, "");

export const shaHashWithSecret = (data, secret) => {
  return crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace("=", "");
};
