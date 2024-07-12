import jwt from "jsonwebtoken";
import { JWT_SECRET } from "../config.js";
import express from "express";

const authMiddleware = (req, res, next) => {
  //imp thing to know that here you req for authorization not authorizations

  const token = req.headers.authorization;

  if (!token || !token.startsWith("Bearer ")) {
    return res.status(403).json({ msg: "token not provided" });
  }

  //if token found to be given

  const validtoken = token.split(" ")[1];

  try {
    const decoded = jwt.verify(validtoken, JWT_SECRET);
    console.log(decoded);

    //so if decoded is true then it will give us that object with all things like username and _id

    req.userid = decoded.userid;

    next();
  } catch (error) {
    res.status(404).json({ msg: "token not valid " });
  }
};

export default authMiddleware;
