import express from "express";
import { Account } from "../models/User.model.js";
import authMiddleware from "../middlewares/middleware.js";
import mongoose from "mongoose";

const router = express.Router();

router.get("/balance", authMiddleware, async (req, res) => {
  try {
    const userid = req.userid;
    const account = await Account.findOne({ userid });
    // console.log(account)
    if (!account) {
      res.status(404).json({ msg: "account not found" });
    }
    const accountbalance = account.balance;

    res.json({ accountbalance });
  } catch (error) {
    res.json({ msg: "error while getting account balance", error });
  }
});

router.post("/transfer", authMiddleware, async (req, res) => {
  const session = await mongoose.startSession();

  try {
    session.startTransaction();

    const { to, amount } = req.body;
    const userid = req.userid;
    const balanceaccount = await Account.findOne({ userid });
    if (!balanceaccount || balanceaccount.balance < amount) {
      return res.status(400).json({ msg: "insufficient account" });
    }

    const toaccount = await Account.findOne({ userid: to });
    if (!toaccount) {
      await session.abortTransaction();
      return res.json({ msg: "no account found" });
    }

    await Account.updateOne({ userid: userid }, { $inc: { balance: -amount } });
    await Account.updateOne({ userid: to }, { $inc: { balance: +amount } });

    await session.commitTransaction();

    res.json({ msg: "money transfer successfully" });
  } catch (error) {
    res.json({ msg: "error while sending amount " });
  }
});

export default router;
