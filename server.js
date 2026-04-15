const express = require("express");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const userRoutes = require("./routes/userRoutes");

dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use("/api", userRoutes);

const PORT = process.env.PORT;
const MONGO_URL = process.env.MONGODB_URL;

mongoose
    .connect(MONGO_URL)
    .then(() => {
        console.log("DB connected successfully");
        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });
    })
    .catch((error) => {
        console.log("DB connection error:", error.message);
    });