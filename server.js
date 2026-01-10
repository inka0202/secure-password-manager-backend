const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());


mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB error:', err));

const authRoutes = require('./routes/authRoutes');
const passwordManagerRoutes = require('./routes/passwordManagerRoute');
const adminRoutes = require('./routes/adminRoutes');
app.use('/api/auth', authRoutes);
app.use('/api/passwords', passwordManagerRoutes);
app.use('/api/admin', adminRoutes); 
app.use(cors({
  origin: [ 
    "http://localhost:3000"                  
  ],
  credentials: true
}));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
