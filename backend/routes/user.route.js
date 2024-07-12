import express from "express";
import { Account, User } from "../models/User.model.js";
import zod from "zod";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";



import authMiddleware from "../middlewares/middleware.js";

let JWT_SECRET  = process.env.JWT_SECRET || "dosomething";
console.log(JWT_SECRET);
const router = express.Router();
const uservalidation = zod.object({
  username: zod.string(),
  password: zod.string(),
  firstname: zod.optional(zod.string()),
  lastname: zod.optional(zod.string()),
});

router.post("/signup", async (req, res) => {
  const { username, password, firstname, lastname } = req.body;

  try {
    const validuser = uservalidation.safeParse({
      username: username,
      password: password,
      firstname: firstname,
      lastname: lastname,
    });
    if (!validuser.success) {
      return res.json({ msg: "credentials should be in a alphabets" });
    }
    const existinguser = await User.findOne({ username });
    if (existinguser) {
      return res.json({ msg: "user already exists" });
    }
    const hashedpassword = bcryptjs.hashSync(password, 10);
    const newuser = new User({
      username,
      password: hashedpassword,
      firstname,
      lastname,
    });

    const userid = newuser._id;

    const newaccount = new Account({
      userid,
      balance: Math.floor(Math.random() * 10000) + 1,
    });
    if (!newaccount) {
      return res.json({
        msg: "error while seding money to each account during signup",
      });
    }

    const token = jwt.sign({ userid }, JWT_SECRET);

    await newuser.save();
    await newaccount.save();

    res.status(200).json({ msg: "new user created", token });
  } catch (error) {
    console.log("eror while signup")
    res.status(404).json({ msg: "error during user registration Try Again" });
  }
});

router.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  try {
    const validuser = uservalidation.safeParse({ username, password });
    if (!validuser.success) {
      return res
        .status(400)
        .json({ msg: "Credentials should be in alphabets" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ msg: "User does not exist" });
    }

    const isPasswordValid = bcryptjs.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ msg: "Invalid password" });
    }

    const token = jwt.sign({ userid: user._id }, JWT_SECRET);

    res
      .status(200)
      .json({ msg: "User logged in successfully", token, userid: user._id });
  } catch (error) {
    console.error("Error while signin:", error);
    res.status(500).json({ msg: "Error while signing in", error });
  }
});

router.put("/update", authMiddleware, async (req, res) => {
  const { password, firstname, lastname } = req.body;

  const updateverification = zod.object({
    password: zod.string().optional(),
    firstname: zod.string().optional(),
    lastname: zod.string().optional(),
  });

  const validuser = updateverification.safeParse({
    password,
    firstname,
    lastname,
  });

  try {
    if (!validuser.success) {
      res.json({ msg: "credentials not fit" });
    }

    const filter = { _id: req.userid };

    const updatefields = {};
    if (password) {
      const newhashpass = bcryptjs.hashSync(password, 10);
      updatefields.password = newhashpass;
    }
    if (firstname) updatefields.firstname = firstname;
    if (lastname) updatefields.lastname = lastname;

    const updateuser = await User.updateOne({ _id: req.userid }, updatefields);

    if (!updateuser) {
      res.status(404).json({ msg: "error while users credentials updation" });
    }

    if (updateuser.nModified === 0) {
      return res
        .status(404)
        .json({ msg: "No user found or no modifications made" });
    }

    res.status(200).json({ msg: "Credentials successfully updated" });
  } catch (error) {
    // console.log(error)
    res.json({ msg: "updation failed", error });
  }
});

router.get("/bulk", async (req, res) => {
  const filter = req.query.filter || "";
  const finalfilter = filter.toLowerCase();

  try {
    const users = await User.find({
      $or: [
        {
          firstname: {
            $regex: finalfilter,
            $options: "i",
          },
        },
        {
          lastname: {
            $regex: finalfilter,
            $options: "i",
          },
        },
      ],
    });

    res.json({
      user: users.map((user) => ({
        username: user.username,
        firstname: user.firstname,
        lastname: user.lastname,
        _id: user._id,
      })),
    });
  } catch (error) {
    return res.status(400).json({ msg: "error while seaching user", error });
  }
});

export default router;
