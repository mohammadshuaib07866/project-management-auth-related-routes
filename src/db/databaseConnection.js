import mongoose from "mongoose";

const connectDB = async () => {
  try {
    mongoose.connect(process.env.MONGODB_URL);
  } catch (error) {
    console.error("MongoDB Connection Error", error);
  }
};


export default connectDB;