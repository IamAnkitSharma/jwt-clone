import express from "express";
import { secret } from "./constant.js";
import { sign, verify } from "./token.js";
const app = express();

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
