import express from "express";
const app = express();


import {
  base64ToString,
  convertToBase64,
  removeEqualsChar,
  shaHashWithSecret,
} from "./utils.js";
import { headerInfo, secret } from "./constant.js";

const sign = (data, secret, seconds) => {
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

const verify = (data, secret) => {
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

app.get("/login", (req, res) => {
  const userId = req.query.userId || "test";
  res.json({
    token: sign(
      {
        _id: userId,
      },
      secret,
      req.query.expiry ? parseInt(req.query.expiry) : 30
    ),
  });
});

app.get("/verify/", (req, res) => {
  const token = req.headers["token"] || req.query.token;
  try {
    const user = verify(token, secret);
    res.json(user);
  } catch (error) {
    console.log(error);
    res.status(401).send({
      error: "Unauthorized",
    });
  }
});

app.listen(5000, () => {
  console.log("App listening on port 5000");
});
