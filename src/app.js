import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import healthCheckRoute from "./routes/healthcheck.route.js";
import authRoutes from "./routes/auth.route.js";
import cookieParser from "cookie-parser";

dotenv.config({ path: "./.env" });

const app = express();

// Middlewares
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));

app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || ["http://localhost:5173"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  })
);
app.use(cookieParser())
// Default route
app.get("/api/v1/", (req, res) => {
  res.send("Welcome to project management");
});

// Health check route
app.use("/api/v1/healthcheck", healthCheckRoute);
app.use("/api/v1/users",authRoutes)

export default app;
