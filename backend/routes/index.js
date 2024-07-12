import express from "express";

import userroute from "./user.route.js";
import accountroute from "./account.route.js";

const router = express.Router();

router.use("/user", userroute);
router.use("/account", accountroute);

export default router;
