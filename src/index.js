import http from "http";
import app from "./app.js";
import connectDB from "./db/databaseConnection.js";

const PORT = process.env.PORT || 3000;

const server = http.createServer(app);

(async () => {
  try {
    await connectDB();
    console.log("Database connected successfully");

    server.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Database connection failed:", error);
    process.exit(1); // stop server if DB not connected
  }
})();
