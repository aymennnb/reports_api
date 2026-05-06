const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const userRoutes = require("./routes/userRoutes");
const vulnerabilityRoutes = require('./routes/vulnerabilityRoutes')
const incidentsRoutes = require('./routes/incidentsRoutes');
const importLogsRoutes = require("./routes/importLogsRoutes");
const { initScheduler } = require("./services/schedulerService");

dotenv.config();
const app = express();

app.use(bodyParser.json());

const corsPort = process.env.PORTCLIENT;
const corsOptions = {
  origin: [`http://localhost:${corsPort}`]
};
app.use(cors(corsOptions));

app.use("/api", userRoutes);
app.use("/api", vulnerabilityRoutes);
app.use('/api', incidentsRoutes);
app.use("/api/import-logs", importLogsRoutes);

const PORT = process.env.PORT;
const MONGO_URL = process.env.MONGODB_URL;

mongoose
    .connect(MONGO_URL)
    .then(async () => {
        console.log("DB connected successfully");

        await initScheduler();

        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });
    })
    .catch((error) => {
        console.log("DB connection error:", error.message);
    });