const express = require('express');
const app = express();
const dotenv = require('dotenv');
const connectMongoDB = require('./config/mongodb');
const incidentRoutes = require('./routes/incidentRoutes');
const scanRoutes = require('./routes/scanRoutes');
// const vulnerabilityRoutes = require('./routes/vulnerabilityRoutes');
// const userRoutes = require('./routes/userRoutes');
const errorhandler = require('./middlewares/errorHandler');
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));
const { startEmailListener } = require('./services/emailListener');
startEmailListener();
dotenv.config();
const PORT = process.env.PORT || 3000;
const { startWazuhAlertListener } = require('./services/wazuhAlertListener');


// Connexion à MongoDB
connectMongoDB()
.then(() => {
    console.log('MongoDB connecté');
    startWazuhAlertListener();
});

app.use(express.json());

// Routes
app.use('/api/incidents', incidentRoutes);
app.use('/api/scans', scanRoutes);
// app.use('/api/vulnerabilities', vulnerabilityRoutes);
// app.use('/api/users', userRoutes);

app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the Express API!' });
});

// Error handling middleware 
app.use(errorhandler);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
