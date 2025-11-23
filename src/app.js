import dotenv from "dotenv";
import express from "express";

dotenv.config({ path: "./.env" });

const app = express();

// Routes
app.get("/", (req, res) => {
  res.send("Welcome to project management");
});

export default app;
