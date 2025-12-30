const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Restaurant Reservation Backend is running 🚀");
});

app.post("/api/test", (req, res) => {
  res.json({ success: true });
});

module.exports = app;
