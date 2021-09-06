import * as dotenv from "dotenv";
dotenv.config(".env");

export const secret = process.env.SECRET || "sample secret";
export const headerInfo = {
  type: "JWT",
  alg: "HS256",
};
