// =======================================================
// FILE: package.json
// =======================================================
{
  "name": "crowdresolve-backend",
  "version": "1.0.0",
  "description": "Backend for CrowdResolve civic issue reporting platform",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "keywords": [],
  "author": "",
  "license": "MIT",
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.5.0"
  },
  "devDependencies": {
    "nodemon": "^3.1.0"
  }
}

// =======================================================
// FILE: .env   (create this file in the project root)
// =======================================================
// ⚠️ Do NOT commit this to GitHub with real values
PORT=4000
MONGO_URI=mongodb://127.0.0.1:27017/crowdresolve
JWT_SECRET=your_super_secret_key_here
FRONTEND_ORIGIN=https://crowdresolve-ai-driv-yt217xb7.sites.blink.new

// =======================================================
// FILE: server.js
// =======================================================
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const connectDB = require("./src/config/db");
const authRoutes = require("./src/routes/authRoutes");
const issueRoutes = require("./src/routes/issueRoutes");
const { protect } = require("./src/middleware/auth");

dotenv.config();
connectDB();

const app = express();

// Parse JSON bodies
app.use(express.json());

// CORS – allow your Builder.io site
const allowedOrigin = process.env.FRONTEND_ORIGIN || "*";
app.use(
  cors({
    origin: allowedOrigin,
    credentials: true,
  })
);

// Health check
app.get("/", (req, res) => {
  res.json({ message: "CrowdResolve backend is running" });
});

// Auth routes
app.use("/api/auth", authRoutes);

// Protected "me" route
app.get("/api/auth/me", protect, (req, res) => {
  res.json(req.user);
});

// Issue routes
app.use("/api/issues", issueRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);

// =======================================================
// FILE: src/config/db.js
// =======================================================
const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  }
};

module.exports = connectDB;

// =======================================================
// FILE: src/models/User.js
// =======================================================
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    role: {
      type: String,
      enum: ["citizen", "official", "admin"],
      default: "citizen",
    }
  },
  { timestamps: true }
);

// Hash password before save
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Compare password method
userSchema.methods.matchPassword = async function (enteredPassword) {
  return bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model("User", userSchema);

// =======================================================
// FILE: src/models/Issue.js
// =======================================================
const mongoose = require("mongoose");

const issueSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    category: {
      type: String,
      default: "Uncategorized",
    },
    priority: {
      type: String,
      enum: ["Low", "Medium", "High"],
      default: "Medium",
    },
    status: {
      type: String,
      enum: ["Open", "In Progress", "Resolved", "Rejected"],
      default: "Open",
    },
    locationText: {
      type: String,
    },
    latitude: {
      type: Number,
    },
    longitude: {
      type: Number,
    },
    imageUrl: {
      type: String,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    assignedToDept: {
      type: String,
    },
    aiSummary: {
      type: String,
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Issue", issueSchema);

// =======================================================
// FILE: src/middleware/auth.js
// =======================================================
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const protect = async (req, res, next) => {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return res.status(401).json({ message: "Not authorized, no token" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select("-password");
    if (!req.user) {
      return res.status(401).json({ message: "User no longer exists" });
    }
    next();
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "Not authorized, token failed" });
  }
};

const requireRole = (roles = []) => {
  if (typeof roles === "string") roles = [roles];

  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden: insufficient role" });
    }
    next();
  };
};

module.exports = { protect, requireRole };

// =======================================================
// FILE: src/routes/authRoutes.js
// =======================================================
const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

// POST /api/auth/register
router.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: "User already exists" });
    }

    const user = await User.create({
      name,
      email,
      password,
      role: role || "citizen",
    });

    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      token: generateToken(user._id),
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /api/auth/login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      token: generateToken(user._id),
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;

// =======================================================
// FILE: src/routes/issueRoutes.js
// =======================================================
const express = require("express");
const Issue = require("../models/Issue");
const { protect, requireRole } = require("../middleware/auth");

const router = express.Router();

/**
 * Simple auto-categorization (placeholder for AI).
 * You can later replace this with an LLM call.
 */
function autoCategorizeIssue(title, description) {
  const text = (title + " " + description).toLowerCase();

  let category = "Uncategorized";
  let priority = "Medium";
  let assignedToDept = "General";

  if (text.includes("pothole") || text.includes("road") || text.includes("street")) {
    category = "Road / Pothole";
    assignedToDept = "Roads Department";
    priority = "High";
  } else if (text.includes("water") || text.includes("sewage") || text.includes("drain")) {
    category = "Water / Drainage";
    assignedToDept = "Water Department";
  } else if (text.includes("garbage") || text.includes("trash") || text.includes("waste")) {
    category = "Garbage / Sanitation";
    assignedToDept = "Sanitation Department";
  } else if (text.includes("light") || text.includes("electric")) {
    category = "Street Light / Electricity";
    assignedToDept = "Electricity Department";
  }

  if (text.includes("accident") || text.includes("danger") || text.includes("injury")) {
    priority = "High";
  }

  const aiSummary =
    description.length > 120
      ? description.slice(0, 117) + "..."
      : description;

  return { category, priority, assignedToDept, aiSummary };
}

// POST /api/issues  (citizen creates issue)
router.post("/", protect, async (req, res) => {
  try {
    const {
      title,
      description,
      locationText,
      latitude,
      longitude,
      imageUrl,
    } = req.body;

    if (!title || !description) {
      return res.status(400).json({ message: "Title and description are required" });
    }

    const { category, priority, assignedToDept, aiSummary } =
      autoCategorizeIssue(title, description);

    const issue = await Issue.create({
      title,
      description,
      locationText,
      latitude,
      longitude,
      imageUrl,
      createdBy: req.user._id,
      category,
      priority,
      assignedToDept,
      aiSummary,
    });

    res.status(201).json(issue);
  } catch (err) {
    console.error("Create issue error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /api/issues/my  (logged-in user's own issues)
router.get("/my", protect, async (req, res) => {
  try {
    const issues = await Issue.find({ createdBy: req.user._id }).sort({
      createdAt: -1,
    });
    res.json(issues);
  } catch (err) {
    console.error("Get my issues error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /api/issues  (official/admin: view all issues)
router.get("/", protect, requireRole(["official", "admin"]), async (req, res) => {
  try {
    const { status, category, priority } = req.query;

    const filter = {};
    if (status) filter.status = status;
    if (category) filter.category = category;
    if (priority) filter.priority = priority;

    const issues = await Issue.find(filter)
      .populate("createdBy", "name email")
      .sort({ createdAt: -1 });

    res.json(issues);
  } catch (err) {
    console.error("Get all issues error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /api/issues/:id
router.get("/:id", protect, async (req, res) => {
  try {
    const issue = await Issue.findById(req.params.id).populate(
      "createdBy",
      "name email"
    );
    if (!issue) {
      return res.status(404).json({ message: "Issue not found" });
    }

    if (
      req.user.role === "citizen" &&
      issue.createdBy._id.toString() !== req.user._id.toString()
    ) {
      return res.status(403).json({ message: "Forbidden" });
    }

    res.json(issue);
  } catch (err) {
    console.error("Get issue by id error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// PATCH /api/issues/:id/status  (only official/admin)
router.patch("/:id/status", protect, requireRole(["official", "admin"]), async (req, res) => {
  try {
    const { status } = req.body;
    const allowed = ["Open", "In Progress", "Resolved", "Rejected"];
    if (!allowed.includes(status)) {
      return res.status(400).json({ message: "Invalid status" });
    }

    const issue = await Issue.findById(req.params.id);
    if (!issue) {
      return res.status(404).json({ message: "Issue not found" });
    }

    issue.status = status;
    await issue.save();
    res.json(issue);
  } catch (err) {
    console.error("Update status error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
