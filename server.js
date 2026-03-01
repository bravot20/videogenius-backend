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
app.use(express.json());

// In-memory storage
const users = new Map();
const videos = new Map();

// Demo videos
const demoVideos = [
  { url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/Sintel.mp4', duration: '14:48' },
  { url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4', duration: '9:56' },
  { url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/TearsOfSteel.mp4', duration: '12:14' },
  { url: 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ElephantsDream.mp4', duration: '10:53' }
];

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access denied' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'videogenius-secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    if (users.has(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    
    const user = {
      id: userId,
      email,
      password: hashedPassword,
      name,
      plan: 'free',
      videosCreated: 0,
      videoLimit: 3,
      createdAt: new Date().toISOString()
    };
    
    users.set(email, user);
    
    const token = jwt.sign(
      { userId: user.id, email: user.email, plan: user.plan },
      process.env.JWT_SECRET || 'videogenius-secret-key',
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
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
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = users.get(email);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign(
      { userId: user.id, email: user.email, plan: user.plan },
      process.env.JWT_SECRET || 'videogenius-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
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
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    plan: user.plan,
    videosCreated: user.videosCreated,
    videoLimit: user.videoLimit
  });
});

// Video Routes
app.get('/api/videos', authenticateToken, (req, res) => {
  const userVideos = Array.from(videos.values())
    .filter(v => v.userId === req.user.userId)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  
  res.json(userVideos);
});

app.post('/api/videos', authenticateToken, async (req, res) => {
  try {
    const user = Array.from(users.values()).find(u => u.id === req.user.userId);
    
    if (user.videosCreated >= user.videoLimit) {
      return res.status(403).json({ 
        error: 'Video limit reached. Please upgrade your plan.',
        upgradeRequired: true 
      });
    }
    
    const { title, prompt, script, duration, style } = req.body;
    const videoId = uuidv4();
    
    const demoIndex = Math.abs(prompt.split('').reduce((a, b) => a + b.charCodeAt(0), 0)) % demoVideos.length;
    const selectedDemo = demoVideos[demoIndex];
    
    const video = {
      id: videoId,
      userId: req.user.userId,
      title: title || 'Untitled Video',
      prompt,
      script: script || `AI-generated script based on: ${prompt}`,
      duration: duration || '30s',
      style: style || 'cinematic',
      status: 'processing',
      progress: 0,
      url: null,
      thumbnail: `https://picsum.photos/seed/${videoId}/640/360`,
      createdAt: new Date().toISOString()
    };
    
    videos.set(videoId, video);
    
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 15;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        video.status = 'completed';
        video.progress = 100;
        video.url = selectedDemo.url;
        video.duration = selectedDemo.duration;
        user.videosCreated++;
      } else {
        video.progress = Math.round(progress);
      }
    }, 2000);
    
    res.status(201).json(video);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/videos/:id/progress', authenticateToken, (req, res) => {
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
});

app.delete('/api/videos/:id', authenticateToken, (req, res) => {
  const video = videos.get(req.params.id);
  if (!video || video.userId !== req.user.userId) {
    return res.status(404).json({ error: 'Video not found' });
  }
  
  videos.delete(req.params.id);
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  if (user && user.videosCreated > 0) user.videosCreated--;
  
  res.json({ message: 'Video deleted successfully' });
});

// AI Script Generation
app.post('/api/ai/generate-script', authenticateToken, async (req, res) => {
  try {
    const { prompt, duration, tone } = req.body;
    
    const scripts = {
      promotional: `Introducing an amazing solution for your needs! Our product delivers exceptional results that will transform your experience.`,
      educational: `Welcome to this educational journey. Today we'll explore fascinating concepts that will expand your understanding.`,
      storytelling: `Once upon a time, in a world full of possibilities, a remarkable story began.`,
      professional: `In today's competitive landscape, efficiency and innovation are paramount.`
    };
    
    const selectedTone = tone || 'promotional';
    const baseScript = scripts[selectedTone] || scripts.promotional;
    const customizedScript = `${baseScript}\n\nCustomized for: ${prompt}\n\nOptimized for ${duration || '30 second'} video.`;
    
    res.json({
      script: customizedScript,
      wordCount: customizedScript.split(' ').length,
      estimatedDuration: duration || '30s'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== 6 SUBSCRIPTION PLANS ==========
app.get('/api/subscriptions/plans', (req, res) => {
  res.json({
    plans: [
      {
        id: 'free',
        name: 'Free',
        description: 'Get started with AI video generation',
        price: { monthly: 0, yearly: 0 },
        features: [
          '3 videos per month',
          '480p video quality',
          'Basic AI script generation',
          'Community support'
        ],
        limits: { videosPerMonth: 3, quality: '480p', maxDuration: '30s' }
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
          'Standard AI script generation',
          'Email support',
          'Basic analytics'
        ],
        limits: { videosPerMonth: 15, quality: '720p', maxDuration: '1min' }
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
          'Advanced AI script generation',
          'Priority email support',
          'Detailed analytics',
          'Custom thumbnails'
        ],
        limits: { videosPerMonth: 30, quality: '720p', maxDuration: '2min' }
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
          'Premium AI script generation',
          'Priority support',
          'Advanced analytics',
          'Custom branding',
          'API access'
        ],
        limits: { videosPerMonth: 60, quality: '1080p', maxDuration: '5min' }
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
          'Premium AI script generation',
          'Priority support + Chat',
          'Team collaboration (3 members)',
          'Full API access',
          'White-label options'
        ],
        limits: { videosPerMonth: -1, quality: '1080p', maxDuration: '10min' }
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

app.post('/api/subscriptions/checkout', authenticateToken, async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: 'Stripe not configured' });
    
    const { priceId, planId } = req.body;
    const user = Array.from(users.values()).find(u => u.id === req.user.userId);
    
    const session = await stripe.checkout.sessions.create({
      customer_email: user.email,
      line_items: [{ price: priceId, quantity: 1 }],
      mode: 'subscription',
      success_url: `https://bbtnz4pu4rnpm.ok.kimi.link/dashboard?subscription=success&plan=${planId}`,
      cancel_url: `https://bbtnz4pu4rnpm.ok.kimi.link/pricing?canceled=true`,
      metadata: { userId: user.id, planId: planId }
    });
    
    res.json({ url: session.url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dashboard Stats
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
  const userVideos = Array.from(videos.values()).filter(v => v.userId === req.user.userId);
  const user = Array.from(users.values()).find(u => u.id === req.user.userId);
  
  res.json({
    totalVideos: userVideos.length,
    videosThisMonth: userVideos.filter(v => {
      const created = new Date(v.createdAt);
      const now = new Date();
      return created.getMonth() === now.getMonth() && created.getFullYear() === now.getFullYear();
    }).length,
    totalViews: userVideos.reduce((sum, v) => sum + (v.views || 0), 0),
    remainingVideos: user.videoLimit === -1 ? 'Unlimited' : user.videoLimit - user.videosCreated,
    plan: user.plan
  });
});

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    stripe: stripe ? 'connected' : 'not configured'
  });
});

// Root
app.get('/', (req, res) => {
  res.json({
    name: 'VideoGenius API',
    version: '1.0.0',
    status: 'running',
    plans: 6
  });
});

app.listen(PORT, () => {
  console.log(`VideoGenius API running on port ${PORT}`);
});
