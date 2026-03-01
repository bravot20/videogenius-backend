const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Stripe = require('stripe');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Stripe
const stripe = process.env.STRIPE_SECRET_KEY 
  ? new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' })
  : null;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// In-memory storage with better structure
const users = new Map();
const videos = new Map();
const subscriptions = new Map();

// Demo videos for generation
const demoVideos = [
  { url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/Sintel.mp4', duration: '14:48', title: 'Sintel' },
  { url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4', duration: '9:56', title: 'Big Buck Bunny' },
  { url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/TearsOfSteel.mp4', duration: '12:14', title: 'Tears of Steel' },
  { url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4', duration: '10:53', title: 'Elephants Dream' }
];

// Plan configuration with video limits and durations
const PLAN_CONFIG = {
  free: { videosPerMonth: 3, maxDurationMinutes: 3, quality: '480p' },
  lite: { videosPerMonth: 15, maxDurationMinutes: 5, quality: '720p' },
  plus: { videosPerMonth: 30, maxDurationMinutes: 7, quality: '720p' },
  pro: { videosPerMonth: 60, maxDurationMinutes: 10, quality: '1080p' },
  business: { videosPerMonth: -1, maxDurationMinutes: 15, quality: '1080p' },
  enterprise: { videosPerMonth: -1, maxDurationMinutes: 999, quality: '4K' }
};

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'videogenius-secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ error: 'Token expired. Please login again.' });
    }
    return res.status(403).json({ error: 'Invalid token.' });
  }
};

// Input validation helper
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  return password && password.length >= 6;
};

// Error handler wrapper
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ===== AUTH ROUTES =====

// Register with validation
app.post('/api/auth/register', asyncHandler(async (req, res) => {
  const { email, password, name } = req.body;
  
  // Validation
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Please provide email, password, and name' });
  }
  
  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Please provide a valid email address' });
  }
  
  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  if (name.length < 2) {
    return res.status(400).json({ error: 'Name must be at least 2 characters' });
  }
  
  // Check if user exists
  if (users.has(email.toLowerCase())) {
    return res.status(409).json({ error: 'User already exists with this email' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = uuidv4();
  
  const user = {
    id: userId,
    email: email.toLowerCase(),
    password: hashedPassword,
    name: name.trim(),
    plan: 'free',
    videosCreated: 0,
    videoLimit: PLAN_CONFIG.free.videosPerMonth,
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString()
  };
  
  users.set(email.toLowerCase(), user);
  
  const token = jwt.sign(
    { userId: user.id, email: user.email, plan: user.plan },
    process.env.JWT_SECRET || 'videogenius-secret-key',
    { expiresIn: '7d' }
  );
  
  res.status(201).json({
    success: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      plan: user.plan,
      videosCreated: user.videosCreated,
      videoLimit: user.videoLimit
    }
  });
}));

// Login with validation
app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Please provide email and password' });
  }
  
  const user = users.get(email.toLowerCase());
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  
  // Update last login
  user.lastLogin = new Date().toISOString();
  
  const token = jwt.sign(
    { userId: user.id, email: user.email, plan: user.plan },
    process.env.JWT_SECRET || 'videogenius-secret-key',
    { expiresIn: '7d' }
  );
  
  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      plan: user.plan,
      videosCreated: user.videosCreated,
      videoLimit: user.videoLimit
    }
  });
}));

// Get current user
app.get('/api/auth/me', authenticateToken, asyncHandler(async (req, res) => {
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    plan: user.plan,
    videosCreated: user.videosCreated,
    videoLimit: user.videoLimit
  });
}));

// ===== VIDEO ROUTES =====

// Get all videos for user with pagination
app.get('/api/videos', authenticateToken, asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  
  let userVideos = Array.from(videos.values())
    .filter(v => v.userId === req.user.userId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  
  const total = userVideos.length;
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  
  userVideos = userVideos.slice(startIndex, endIndex);
  
  res.json({
    videos: userVideos,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit)
    }
  });
}));

// Get single video
app.get('/api/videos/:id', authenticateToken, asyncHandler(async (req, res) => {
  const video = videos.get(req.params.id);
  if (!video || video.userId !== req.user.userId) {
    return res.status(404).json({ error: 'Video not found' });
  }
  
  res.json(video);
}));

// Parse duration string to minutes
const parseDuration = (durationStr) => {
  if (!durationStr) return 0;
  const match = durationStr.match(/(\d+)/);
  return match ? parseInt(match[1]) : 0;
};

// Create video with plan validation
app.post('/api/videos', authenticateToken, asyncHandler(async (req, res) => {
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // Check video limit
  if (user.videoLimit !== -1 && user.videosCreated >= user.videoLimit) {
    return res.status(403).json({ 
      error: 'Video limit reached. Please upgrade your plan.',
      upgradeRequired: true,
      current: user.videosCreated,
      limit: user.videoLimit
    });
  }
  
  const { title, prompt, script, duration, style } = req.body;
  
  // Validation
  if (!title || !prompt) {
    return res.status(400).json({ error: 'Title and prompt are required' });
  }
  
  if (title.length > 100) {
    return res.status(400).json({ error: 'Title must be less than 100 characters' });
  }
  
  if (prompt.length > 1000) {
    return res.status(400).json({ error: 'Prompt must be less than 1000 characters' });
  }
  
  // Check duration limit based on plan
  const planConfig = PLAN_CONFIG[user.plan] || PLAN_CONFIG.free;
  const requestedDuration = parseDuration(duration);
  const maxDuration = planConfig.maxDurationMinutes;
  
  if (requestedDuration > maxDuration) {
    return res.status(403).json({
      error: `Your ${user.plan} plan allows maximum ${maxDuration} minute videos. Please upgrade for longer videos.`,
      upgradeRequired: true,
      maxAllowed: maxDuration,
      requested: requestedDuration
    });
  }
  
  const videoId = uuidv4();
  
  // Select demo video based on prompt hash
  const demoIndex = Math.abs(prompt.split('').reduce((a, b) => a + b.charCodeAt(0), 0)) % demoVideos.length;
  const selectedDemo = demoVideos[demoIndex];
  
  const video = {
    id: videoId,
    userId: req.user.userId,
    title: title.trim(),
    prompt: prompt.trim(),
    script: script ? script.trim() : `AI-generated script based on: ${prompt}`,
    duration: duration || '30s',
    style: style || 'cinematic',
    status: 'processing',
    progress: 0,
    url: null,
    thumbnail: `https://picsum.photos/seed/${videoId}/640/360`,
    views: 0,
    createdAt: new Date().toISOString(),
    completedAt: null
  };
  
  videos.set(videoId, video);
  
  // Simulate video generation progress
  let progress = 0;
  const interval = setInterval(() => {
    progress += Math.random() * 12 + 5; // Faster progress
    if (progress >= 100) {
      progress = 100;
      clearInterval(interval);
      video.status = 'completed';
      video.progress = 100;
      video.url = selectedDemo.url;
      video.duration = selectedDemo.duration;
      video.completedAt = new Date().toISOString();
      user.videosCreated++;
    } else {
      video.progress = Math.round(progress);
    }
  }, 1500);
  
  res.status(201).json({
    success: true,
    video
  });
}));

// Get video progress
app.get('/api/videos/:id/progress', authenticateToken, asyncHandler(async (req, res) => {
  const video = videos.get(req.params.id);
  if (!video || video.userId !== req.user.userId) {
    return res.status(404).json({ error: 'Video not found' });
  }
  
  res.json({
    id: video.id,
    status: video.status,
    progress: video.progress,
    url: video.url
  });
}));

// Delete video
app.delete('/api/videos/:id', authenticateToken, asyncHandler(async (req, res) => {
  const video = videos.get(req.params.id);
  if (!video || video.userId !== req.user.userId) {
    return res.status(404).json({ error: 'Video not found' });
  }
  
  videos.delete(req.params.id);
  
  // Decrement user's video count
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  if (user && user.videosCreated > 0) {
    user.videosCreated--;
  }
  
  res.json({ 
    success: true,
    message: 'Video deleted successfully' 
  });
}));

// Increment video views
app.post('/api/videos/:id/view', authenticateToken, asyncHandler(async (req, res) => {
  const video = videos.get(req.params.id);
  if (!video || video.userId !== req.user.userId) {
    return res.status(404).json({ error: 'Video not found' });
  }
  
  video.views = (video.views || 0) + 1;
  
  res.json({
    success: true,
    views: video.views
  });
}));

// ===== AI SCRIPT GENERATION =====

app.post('/api/ai/generate-script', authenticateToken, asyncHandler(async (req, res) => {
  const { prompt, duration, tone } = req.body;
  
  if (!prompt) {
    return res.status(400).json({ error: 'Prompt is required' });
  }
  
  const scripts = {
    promotional: `Introducing an amazing solution for your needs! Our product delivers exceptional results that will transform your experience. With cutting-edge technology and user-friendly design, you'll achieve your goals faster than ever before. Don't wait - start your journey to success today!`,
    educational: `Welcome to this educational journey. Today we'll explore fascinating concepts that will expand your understanding. First, let's establish the fundamentals. Then, we'll dive deeper into practical applications. By the end, you'll have a comprehensive grasp of the subject matter.`,
    storytelling: `Once upon a time, in a world full of possibilities, a remarkable story began. Our protagonist faced challenges that seemed insurmountable. But through determination, creativity, and the support of unexpected allies, they discovered their true potential and changed everything.`,
    professional: `In today's competitive landscape, efficiency and innovation are paramount. Our approach combines industry best practices with forward-thinking strategies. The results speak for themselves: increased productivity, reduced costs, and sustainable growth for your organization.`
  };
  
  const selectedTone = tone || 'promotional';
  const baseScript = scripts[selectedTone] || scripts.promotional;
  
  // Customize based on prompt
  const customizedScript = `${baseScript}\n\n---\n\nCustomized for your request: "${prompt}"\n\nThis script is optimized for a ${duration || '30 second'} video format and can be further refined to match your specific needs.`;
  
  res.json({
    success: true,
    script: customizedScript,
    wordCount: customizedScript.split(' ').length,
    estimatedDuration: duration || '30s',
    tone: selectedTone
  });
}));

// ===== SUBSCRIPTION ROUTES =====

// Get all subscription plans
app.get('/api/subscriptions/plans', (req, res) => {
  res.json({
    success: true,
    plans: [
      {
        id: 'free',
        name: 'Free',
        description: 'Get started with AI video generation',
        price: { monthly: 0, yearly: 0 },
        features: [
          '3 videos per month',
          '480p video quality',
          'Up to 3 minutes per video',
          'Basic AI script generation',
          'Community support'
        ],
        limits: { videosPerMonth: 3, quality: '480p', maxDuration: '3min' }
      },
      {
        id: 'lite',
        name: 'Lite',
        description: 'Perfect for casual creators',
        price: { monthly: 7, yearly: 70 },
        priceIds: {
          monthly: process.env.STRIPE_PRICE_LITE_MONTHLY || '',
          yearly: process.env.STRIPE_PRICE_LITE_YEARLY || ''
        },
        features: [
          '15 videos per month',
          '720p HD video quality',
          'Up to 5 minutes per video',
          'Standard AI script generation',
          'Email support',
          'Basic analytics'
        ],
        limits: { videosPerMonth: 15, quality: '720p', maxDuration: '5min' }
      },
      {
        id: 'plus',
        name: 'Plus',
        description: 'For growing content creators',
        price: { monthly: 15, yearly: 150 },
        priceIds: {
          monthly: process.env.STRIPE_PRICE_PLUS_MONTHLY || '',
          yearly: process.env.STRIPE_PRICE_PLUS_YEARLY || ''
        },
        features: [
          '30 videos per month',
          '720p HD video quality',
          'Up to 7 minutes per video',
          'Advanced AI script generation',
          'Priority email support',
          'Detailed analytics',
          'Custom thumbnails'
        ],
        limits: { videosPerMonth: 30, quality: '720p', maxDuration: '7min' }
      },
      {
        id: 'pro',
        name: 'Pro',
        description: 'For serious creators and influencers',
        price: { monthly: 29, yearly: 290 },
        priceIds: {
          monthly: process.env.STRIPE_PRICE_PRO_MONTHLY || '',
          yearly: process.env.STRIPE_PRICE_PRO_YEARLY || ''
        },
        features: [
          '60 videos per month',
          '1080p Full HD quality',
          'Up to 10 minutes per video',
          'Premium AI script generation',
          'Priority support',
          'Advanced analytics',
          'Custom branding',
          'API access'
        ],
        limits: { videosPerMonth: 60, quality: '1080p', maxDuration: '10min' }
      },
      {
        id: 'business',
        name: 'Business',
        description: 'For teams and small agencies',
        price: { monthly: 59, yearly: 590 },
        priceIds: {
          monthly: process.env.STRIPE_PRICE_BUSINESS_MONTHLY || '',
          yearly: process.env.STRIPE_PRICE_BUSINESS_YEARLY || ''
        },
        features: [
          'Unlimited videos',
          '1080p Full HD quality',
          'Up to 15 minutes per video',
          'Premium AI script generation',
          'Priority support + Chat',
          'Team collaboration (3 members)',
          'Full API access',
          'White-label options'
        ],
        limits: { videosPerMonth: -1, quality: '1080p', maxDuration: '15min' }
      },
      {
        id: 'enterprise',
        name: 'Enterprise',
        description: 'For large teams and agencies',
        price: { monthly: 99, yearly: 990 },
        priceIds: {
          monthly: process.env.STRIPE_PRICE_ENTERPRISE_MONTHLY || '',
          yearly: process.env.STRIPE_PRICE_ENTERPRISE_YEARLY || ''
        },
        features: [
          'Unlimited everything',
          '4K Ultra HD quality',
          'Unlimited video length',
          'Custom AI training',
          'Dedicated account manager',
          'Unlimited team members',
          'Full white-label solution',
          'SSO & advanced security',
          'Custom integrations'
        ],
        limits: { videosPerMonth: -1, quality: '4K', maxDuration: 'unlimited' }
      }
    ]
  });
});

// Create Stripe checkout session
app.post('/api/subscriptions/checkout', authenticateToken, asyncHandler(async (req, res) => {
  if (!stripe) {
    return res.status(500).json({ error: 'Stripe not configured' });
  }
  
  const { priceId, planId } = req.body;
  
  if (!priceId || !planId) {
    return res.status(400).json({ error: 'Price ID and Plan ID are required' });
  }
  
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  try {
    const session = await stripe.checkout.sessions.create({
      customer_email: user.email,
      line_items: [{ price: priceId, quantity: 1 }],
      mode: 'subscription',
      success_url: `https://bbtnz4pu4rnpm.ok.kimi.link/dashboard?subscription=success&plan=${planId}`,
      cancel_url: `https://bbtnz4pu4rnpm.ok.kimi.link/pricing?canceled=true`,
      metadata: { userId: user.id, planId: planId }
    });
    
    res.json({
      success: true,
      url: session.url
    });
  } catch (error) {
    console.error('Stripe checkout error:', error);
    res.status(500).json({ error: 'Failed to create checkout session' });
  }
}));

// Get current subscription
app.get('/api/subscriptions/current', authenticateToken, asyncHandler(async (req, res) => {
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const sub = subscriptions.get(req.user.userId);
  
  res.json({
    plan: user.plan,
    status: sub ? sub.status : 'active',
    currentPeriodEnd: sub ? sub.currentPeriodEnd : null,
    cancelAtPeriodEnd: sub ? sub.cancelAtPeriodEnd : false,
    videosCreated: user.videosCreated,
    videoLimit: user.videoLimit
  });
}));

// ===== ADMIN ROUTES =====

// Admin middleware
const authenticateAdmin = (req, res, next) => {
  const adminSecret = req.headers['x-admin-secret'];
  if (adminSecret !== (process.env.ADMIN_SECRET || 'videogenius-admin-2024')) {
    return res.status(403).json({ error: 'Unauthorized admin access' });
  }
  next();
};

// Upgrade user plan (admin only)
app.post('/api/admin/upgrade-user', authenticateAdmin, asyncHandler(async (req, res) => {
  const { email, plan } = req.body;
  
  if (!email || !plan) {
    return res.status(400).json({ error: 'Email and plan are required' });
  }
  
  const validPlans = ['free', 'lite', 'plus', 'pro', 'business', 'enterprise'];
  if (!validPlans.includes(plan)) {
    return res.status(400).json({ error: 'Invalid plan. Valid plans: ' + validPlans.join(', ') });
  }
  
  const user = users.get(email.toLowerCase());
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  // Update user plan
  const planConfig = PLAN_CONFIG[plan];
  user.plan = plan;
  user.videoLimit = planConfig.videosPerMonth;
  user.upgradedAt = new Date().toISOString();
  user.upgradedBy = 'admin';
  
  // Create subscription record
  subscriptions.set(user.id, {
    userId: user.id,
    plan: plan,
    status: 'active',
    currentPeriodEnd: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
    cancelAtPeriodEnd: false,
    createdAt: new Date().toISOString()
  });
  
  res.json({
    success: true,
    message: `User ${email} upgraded to ${plan} plan successfully`,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      plan: user.plan,
      videoLimit: user.videoLimit,
      upgradedAt: user.upgradedAt
    }
  });
}));

// Get all users (admin only)
app.get('/api/admin/users', authenticateAdmin, asyncHandler(async (req, res) => {
  const allUsers = Array.from(users.values()).map(u => ({
    id: u.id,
    email: u.email,
    name: u.name,
    plan: u.plan,
    videosCreated: u.videosCreated,
    videoLimit: u.videoLimit,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin
  }));
  
  res.json({
    success: true,
    count: allUsers.length,
    users: allUsers
  });
}));

// ===== DASHBOARD STATS =====

app.get('/api/dashboard/stats', authenticateToken, asyncHandler(async (req, res) => {
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const userVideos = Array.from(videos.values()).filter(v => v.userId === req.user.userId);
  
  const now = new Date();
  const currentMonth = now.getMonth();
  const currentYear = now.getFullYear();
  
  const videosThisMonth = userVideos.filter(v => {
    const created = new Date(v.createdAt);
    return created.getMonth() === currentMonth && created.getFullYear() === currentYear;
  });
  
  const totalViews = userVideos.reduce((sum, v) => sum + (v.views || 0), 0);
  
  // Calculate storage used (mock)
  const storageUsed = userVideos.length * 50; // 50MB per video estimate
  
  res.json({
    success: true,
    stats: {
      totalVideos: userVideos.length,
      videosThisMonth: videosThisMonth.length,
      totalViews: totalViews,
      remainingVideos: user.videoLimit === -1 ? 'Unlimited' : Math.max(0, user.videoLimit - user.videosCreated),
      plan: user.plan,
      storageUsed: `${storageUsed} MB`,
      videoLimit: user.videoLimit
    }
  });
}));

// ===== HEALTH & STATUS =====

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    stripe: stripe ? 'connected' : 'not configured',
    uptime: process.uptime()
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'VideoGenius API',
    version: '1.0.0',
    status: 'running',
    endpoints: [
      '/api/health',
      '/api/auth/register',
      '/api/auth/login',
      '/api/auth/me',
      '/api/videos',
      '/api/subscriptions/plans',
      '/api/subscriptions/checkout',
      '/api/subscriptions/current',
      '/api/dashboard/stats',
      '/api/ai/generate-script',
      '/api/admin/upgrade-user',
      '/api/admin/users'
    ]
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 VideoGenius API running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
});
