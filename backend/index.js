import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import router from "./routes/index.js";





const app = express();
dotenv.config();
app.use(cors());

app.use(express.json());
const URI = process.env.DB_URI ;
const PORT = process.env.PORT | 3000;

console.log(URI)
 


app.get("/", (req, res) => {
  res.send("how are you");
});

app.use("/api/v1", router);

app.listen(PORT, async () => {
  try {
    await mongoose
      .connect(URI, {
        dbName: "Paytm",
      })
      .then(console.log(" MONGODB Database connected"));

    console.log(`Connected to http://localhost:${PORT}`);
  } catch (error) {
    console.log("error", error);
    res.json({msg: "error while connecting with databse", error})
  }
});
