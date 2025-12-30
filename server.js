const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/restaurant-reservation', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
  seedTables();
}).catch(err => console.error('MongoDB connection error:', err));

// ==================== SCHEMAS ====================

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['customer', 'admin'], default: 'customer' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Table Schema
const tableSchema = new mongoose.Schema({
  tableNumber: { type: Number, required: true, unique: true },
  capacity: { type: Number, required: true },
  isAvailable: { type: Boolean, default: true }
});

const Table = mongoose.model('Table', tableSchema);

// Reservation Schema
const reservationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tableId: { type: mongoose.Schema.Types.ObjectId, ref: 'Table', required: true },
  reservationDate: { type: String, required: true }, // Format: YYYY-MM-DD
  timeSlot: { type: String, required: true }, // Format: HH:MM
  numberOfGuests: { type: Number, required: true },
  status: { type: String, enum: ['active', 'cancelled'], default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

// Compound index to prevent double bookings
reservationSchema.index({ tableId: 1, reservationDate: 1, timeSlot: 1, status: 1 });

const Reservation = mongoose.model('Reservation', reservationSchema);

// ==================== SEED DATA ====================
async function seedTables() {
  const count = await Table.countDocuments();
  if (count === 0) {
    const tables = [
      { tableNumber: 1, capacity: 2 },
      { tableNumber: 2, capacity: 2 },
      { tableNumber: 3, capacity: 4 },
      { tableNumber: 4, capacity: 4 },
      { tableNumber: 5, capacity: 6 },
      { tableNumber: 6, capacity: 6 },
      { tableNumber: 7, capacity: 8 },
      { tableNumber: 8, capacity: 8 },
      { tableNumber: 9, capacity: 10 }
    ];
    await Table.insertMany(tables);
    console.log('Tables seeded successfully');
  }
}

// ==================== MIDDLEWARE ====================

// Authentication Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key-change-in-production');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    req.userId = user._id;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin Authorization Middleware
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ==================== VALIDATION ====================

const validateReservation = (date, timeSlot, numberOfGuests) => {
  const errors = [];
  
  // Validate date format and future date
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(date)) {
    errors.push('Invalid date format. Use YYYY-MM-DD');
  } else {
    const reservationDate = new Date(date);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (reservationDate < today) {
      errors.push('Reservation date must be today or in the future');
    }
  }

  // Validate time slot format
  const timeRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;
  if (!timeRegex.test(timeSlot)) {
    errors.push('Invalid time format. Use HH:MM (24-hour format)');
  }

  // Validate number of guests
  if (numberOfGuests < 1 || numberOfGuests > 20) {
    errors.push('Number of guests must be between 1 and 20');
  }

  return errors;
};

// ==================== ROUTES ====================

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role: role || 'customer'
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key-change-in-production',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get current user
app.get('/api/auth/me', authenticate, async (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role
    }
  });
});

// Table Routes
app.get('/api/tables', authenticate, async (req, res) => {
  try {
    const tables = await Table.find().sort({ tableNumber: 1 });
    res.json(tables);
  } catch (error) {
    console.error('Error fetching tables:', error);
    res.status(500).json({ error: 'Error fetching tables' });
  }
});

// Get available tables for a specific date, time, and guest count
app.get('/api/tables/available', authenticate, async (req, res) => {
  try {
    const { date, timeSlot, guests } = req.query;

    if (!date || !timeSlot || !guests) {
      return res.status(400).json({ error: 'Date, time slot, and number of guests are required' });
    }

    const numberOfGuests = parseInt(guests);

    // Validate inputs
    const validationErrors = validateReservation(date, timeSlot, numberOfGuests);
    if (validationErrors.length > 0) {
      return res.status(400).json({ error: validationErrors.join(', ') });
    }

    // Find tables with sufficient capacity
    const tablesWithCapacity = await Table.find({ capacity: { $gte: numberOfGuests } });

    // Find existing reservations for this date and time slot
    const existingReservations = await Reservation.find({
      reservationDate: date,
      timeSlot: timeSlot,
      status: 'active'
    }).select('tableId');

    const bookedTableIds = existingReservations.map(r => r.tableId.toString());

    // Filter out booked tables
    const availableTables = tablesWithCapacity.filter(
      table => !bookedTableIds.includes(table._id.toString())
    );

    res.json(availableTables);
  } catch (error) {
    console.error('Error checking availability:', error);
    res.status(500).json({ error: 'Error checking table availability' });
  }
});

// Reservation Routes - Customer
app.post('/api/reservations', authenticate, async (req, res) => {
  try {
    const { tableId, reservationDate, timeSlot, numberOfGuests } = req.body;

    // Validation
    if (!tableId || !reservationDate || !timeSlot || !numberOfGuests) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const validationErrors = validateReservation(reservationDate, timeSlot, numberOfGuests);
    if (validationErrors.length > 0) {
      return res.status(400).json({ error: validationErrors.join(', ') });
    }

    // Check if table exists
    const table = await Table.findById(tableId);
    if (!table) {
      return res.status(404).json({ error: 'Table not found' });
    }

    // Check table capacity
    if (table.capacity < numberOfGuests) {
      return res.status(400).json({ 
        error: `Table capacity (${table.capacity}) is insufficient for ${numberOfGuests} guests` 
      });
    }

    // Check for existing reservation (prevent double booking)
    const existingReservation = await Reservation.findOne({
      tableId,
      reservationDate,
      timeSlot,
      status: 'active'
    });

    if (existingReservation) {
      return res.status(409).json({ 
        error: 'This table is already reserved for the selected date and time slot' 
      });
    }

    // Create reservation
    const reservation = new Reservation({
      userId: req.userId,
      tableId,
      reservationDate,
      timeSlot,
      numberOfGuests,
      status: 'active'
    });

    await reservation.save();

    // Populate table and user info
    await reservation.populate('tableId');
    await reservation.populate('userId', 'name email');

    res.status(201).json({
      message: 'Reservation created successfully',
      reservation
    });
  } catch (error) {
    console.error('Error creating reservation:', error);
    res.status(500).json({ error: 'Error creating reservation' });
  }
});

// Get customer's own reservations
app.get('/api/reservations/my', authenticate, async (req, res) => {
  try {
    const reservations = await Reservation.find({ userId: req.userId })
      .populate('tableId')
      .sort({ reservationDate: -1, timeSlot: -1 });
    
    res.json(reservations);
  } catch (error) {
    console.error('Error fetching reservations:', error);
    res.status(500).json({ error: 'Error fetching reservations' });
  }
});

// Cancel customer's own reservation
app.patch('/api/reservations/:id/cancel', authenticate, async (req, res) => {
  try {
    const reservation = await Reservation.findOne({
      _id: req.params.id,
      userId: req.userId
    });

    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    if (reservation.status === 'cancelled') {
      return res.status(400).json({ error: 'Reservation is already cancelled' });
    }

    reservation.status = 'cancelled';
    await reservation.save();

    await reservation.populate('tableId');
    await reservation.populate('userId', 'name email');

    res.json({
      message: 'Reservation cancelled successfully',
      reservation
    });
  } catch (error) {
    console.error('Error cancelling reservation:', error);
    res.status(500).json({ error: 'Error cancelling reservation' });
  }
});

// Admin Routes
app.get('/api/admin/reservations', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { date } = req.query;
    
    let query = {};
    if (date) {
      query.reservationDate = date;
    }

    const reservations = await Reservation.find(query)
      .populate('tableId')
      .populate('userId', 'name email')
      .sort({ reservationDate: -1, timeSlot: -1 });
    
    res.json(reservations);
  } catch (error) {
    console.error('Error fetching admin reservations:', error);
    res.status(500).json({ error: 'Error fetching reservations' });
  }
});

// Admin cancel any reservation
app.patch('/api/admin/reservations/:id/cancel', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const reservation = await Reservation.findById(req.params.id);

    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    if (reservation.status === 'cancelled') {
      return res.status(400).json({ error: 'Reservation is already cancelled' });
    }

    reservation.status = 'cancelled';
    await reservation.save();

    await reservation.populate('tableId');
    await reservation.populate('userId', 'name email');

    res.json({
      message: 'Reservation cancelled successfully',
      reservation
    });
  } catch (error) {
    console.error('Error cancelling reservation:', error);
    res.status(500).json({ error: 'Error cancelling reservation' });
  }
});

// Admin update reservation
app.patch('/api/admin/reservations/:id', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { tableId, reservationDate, timeSlot, numberOfGuests } = req.body;
    const reservation = await Reservation.findById(req.params.id);

    if (!reservation) {
      return res.status(404).json({ error: 'Reservation not found' });
    }

    if (reservation.status === 'cancelled') {
      return res.status(400).json({ error: 'Cannot update cancelled reservation' });
    }

    // Validate if provided
    if (reservationDate && timeSlot && numberOfGuests) {
      const validationErrors = validateReservation(reservationDate, timeSlot, numberOfGuests);
      if (validationErrors.length > 0) {
        return res.status(400).json({ error: validationErrors.join(', ') });
      }
    }

    // Check for conflicts if date/time/table is being changed
    if (tableId || reservationDate || timeSlot) {
      const checkTableId = tableId || reservation.tableId;
      const checkDate = reservationDate || reservation.reservationDate;
      const checkTime = timeSlot || reservation.timeSlot;

      const conflict = await Reservation.findOne({
        _id: { $ne: req.params.id },
        tableId: checkTableId,
        reservationDate: checkDate,
        timeSlot: checkTime,
        status: 'active'
      });

      if (conflict) {
        return res.status(409).json({ 
          error: 'This table is already reserved for the selected date and time slot' 
        });
      }
    }

    // Check table capacity if changing table or guest count
    if (tableId || numberOfGuests) {
      const checkTableId = tableId || reservation.tableId;
      const checkGuests = numberOfGuests || reservation.numberOfGuests;
      
      const table = await Table.findById(checkTableId);
      if (table && table.capacity < checkGuests) {
        return res.status(400).json({ 
          error: `Table capacity (${table.capacity}) is insufficient for ${checkGuests} guests` 
        });
      }
    }

    // Update fields
    if (tableId) reservation.tableId = tableId;
    if (reservationDate) reservation.reservationDate = reservationDate;
    if (timeSlot) reservation.timeSlot = timeSlot;
    if (numberOfGuests) reservation.numberOfGuests = numberOfGuests;

    await reservation.save();
    await reservation.populate('tableId');
    await reservation.populate('userId', 'name email');

    res.json({
      message: 'Reservation updated successfully',
      reservation
    });
  } catch (error) {
    console.error('Error updating reservation:', error);
    res.status(500).json({ error: 'Error updating reservation' });
  }
});

// Admin manage tables
app.post('/api/admin/tables', authenticate, authorizeAdmin, async (req, res) => {
  try {
    const { tableNumber, capacity } = req.body;

    if (!tableNumber || !capacity) {
      return res.status(400).json({ error: 'Table number and capacity are required' });
    }

    if (capacity < 1 || capacity > 20) {
      return res.status(400).json({ error: 'Capacity must be between 1 and 20' });
    }

    const existingTable = await Table.findOne({ tableNumber });
    if (existingTable) {
      return res.status(400).json({ error: 'Table number already exists' });
    }

    const table = new Table({ tableNumber, capacity });
    await table.save();

    res.status(201).json({
      message: 'Table created successfully',
      table
    });
  } catch (error) {
    console.error('Error creating table:', error);
    res.status(500).json({ error: 'Error creating table' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});