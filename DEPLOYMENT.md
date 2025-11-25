# ThreatSumm4ry Deployment Guide

## 🚀 Deployment Options

### Option 1: Vercel (Recommended - Free Tier)

**100% Open Source Supported**

1. **Install Vercel CLI:**
```bash
npm install -g vercel
```

2. **Deploy:**
```bash
npm run build
vercel --prod
```

3. **Add Environment Variables in Vercel Dashboard:**
   - Go to Project Settings → Environment Variables
   - Add all `VITE_*_API_KEY` variables

**Pros:**
- ✅ Free tier available
- ✅ Automatic HTTPS
- ✅ Global CDN
- ✅ Easy rollbacks
- ✅ Preview deployments for PRs

---

### Option 2: Netlify (Free Tier)

1. **Install Netlify CLI:**
```bash
npm install -g netlify-cli
```

2. **Deploy:**
```bash
npm run build
netlify deploy --prod --dir=dist
```

3. **Or connect GitHub repo:**
   - Push to GitHub
   - Import project in Netlify dashboard
   - Set build command: `npm run build`
   - Set publish directory: `dist`

**Pros:**
- ✅ Free tier available
- ✅ Continuous deployment from Git
- ✅ Form handling
- ✅ Functions support

---

### Option 3: Cloudflare Pages (Free)

1. **Connect GitHub:**
   - Sign up at pages.cloudflare.com
   - Connect your GitHub repository
   - Build command: `npm run build`
   - Output directory: `dist`

2. **Add Environment Variables:**
   - Settings → Environment Variables

**Pros:**
- ✅ Unlimited bandwidth
- ✅ Global CDN
- ✅ DDoS protection
- ✅ Web analytics

---

### Option 4: Self-Hosted (Docker + Nginx)

**Fully Open Source Stack**

**Dockerfile:**
```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**nginx.conf:**
```nginx
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    
    # CSP (Content Security Policy)
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://*.virustotal.com https://*.abuseipdb.com https://*.otx.alienvault.com;" always;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Caching
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

**Deploy:**
```bash
docker build -t threatsumm4ry .
docker run -d -p 80:80 threatsumm4ry
```

---

### Option 5: GitHub Pages (100% Free)

1. **Install gh-pages:**
```bash
npm install --save-dev gh-pages
```

2. **Add to package.json:**
```json
{
  "scripts": {
    "predeploy": "npm run build",
    "deploy": "gh-pages -d dist"
  },
  "homepage": "https://yourusername.github.io/intel-vista-22"
}
```

3. **Update vite.config.ts:**
```typescript
export default defineConfig({
  base: '/intel-vista-22/',
  // ... rest of config
});
```

4. **Deploy:**
```bash
npm run deploy
```

**Limitation:** ⚠️ API keys will be visible in source - use backend proxy for production

---

### Option 6: Render (Recommended for Backend + Frontend)

**Best for full-stack deployment with API proxy**

1. **Create a new Web Service on Render:**
   - Connect your GitHub repository.
   - **Runtime:** Node
   - **Build Command:** `npm install && npm run build && cd server && npm install`
   - **Start Command:** `node server/index.js`
   - **Root Directory:** `.` (default)

2. **Add Environment Variables:**
   - Go to the "Environment" tab.
   - Add all your API keys (without `VITE_` prefix if you updated them, or map them in `server/index.js`):
     - `VIRUSTOTAL_API_KEY`
     - `ABUSEIPDB_API_KEY`
     - ...and so on.
   - Add `NODE_ENV=production`

3. **Deploy:**
   - Render will build the frontend, install backend dependencies, and start the Express server.
   - The Express server is configured to serve the static frontend files from `dist`.

**Pros:**
- ✅ Free tier available
- ✅ Hosted backend for secure API calls
- ✅ Single service for both frontend and backend
- ✅ Automatic HTTPS

---

## 🔐 Secure Deployment with Backend Proxy

### Docker Compose Setup (Recommended for Production)

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  frontend:
    build: .
    ports:
      - "80:80"
    depends_on:
      - backend
    environment:
      - VITE_API_BASE_URL=http://backend:3001

  backend:
    build: ./server
    ports:
      - "3001:3001"
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - SHODAN_API_KEY=${SHODAN_API_KEY}
      # ... other keys
    env_file:
      - .env
```

**Deploy:**
```bash
docker-compose up -d
```

---

## 🛡️ Production Security Checklist

### Before Deployment:

- [ ] Remove or rename `.env.example` to `.env.local`
- [ ] Add `.env` and `.env.*` to `.gitignore`
- [ ] Build production bundle: `npm run build`
- [ ] Test production build locally: `npm run preview`
- [ ] Review environment variables in hosting platform
- [ ] Enable HTTPS (automatic with Vercel/Netlify/Cloudflare)
- [ ] Configure CSP headers
- [ ] Set up rate limiting (if using backend proxy)
- [ ] Test API key restrictions (referrer/IP whitelist)

### Post-Deployment:

- [ ] Verify HTTPS is working
- [ ] Test all vendor integrations
- [ ] Monitor API usage/quotas
- [ ] Set up uptime monitoring (UptimeRobot - free)
- [ ] Configure error tracking (Sentry - free tier)
- [ ] Enable CDN caching
- [ ] Test from different locations (CloudFlare Workers if using CF)

---

## 📊 Free Monitoring Tools (Open Source Alternative)

### Uptime Monitoring:
- **UptimeRobot**: https://uptimerobot.com (Free - 50 monitors)
- **Upptime** (self-hosted): https://github.com/upptime/upptime

### Analytics:
- **Plausible** (self-hosted): https://plausible.io
- **Umami** (self-hosted): https://umami.is
- **Matomo** (self-hosted): https://matomo.org

### Error Tracking:
- **Sentry** (free tier): https://sentry.io
- **GlitchTip** (self-hosted): https://glitchtip.com

---

## 🎯 Recommended Setup for Different Scales

### **Small/Personal Project:**
- Cloudflare Pages or Netlify (Free)
- Client-side API calls (current setup)
- Monitor API quotas manually

### **Medium/Business:**
- Vercel/Netlify + Backend Proxy
- PostgreSQL for caching results
- Rate limiting + API key rotation

### **Large/Enterprise:**
- Self-hosted Docker + Kubernetes
- Redis cache layer
- Load balancer (Nginx/Traefik)
- Dedicated backend API servers

---

## ⚡ Quick Deploy Commands

```bash
# Build for production
npm run build

# Test production build locally
npm run preview

# Deploy to Vercel
vercel --prod

# Deploy to Netlify
netlify deploy --prod --dir=dist

# Deploy with Docker
docker build -t threatsumm4ry .
docker run -d -p 8080:80 threatsumm4ry

# Deploy to GitHub Pages
npm run deploy
```

---

## 🔧 Environment Variable Setup

Create `.env` file (NEVER commit this):

```env
# Threat Intelligence API Keys
VITE_VIRUSTOTAL_API_KEY=your_key_here
VITE_ABUSEIPDB_API_KEY=your_key_here
VITE_ALIENVAULT_API_KEY=your_key_here
VITE_SHODAN_API_KEY=your_key_here
# ... add all 13 API keys
```

For hosting platforms, add these in their dashboard under Environment Variables.

---

## 🎉 Post-Deployment

Your ThreatSumm4ry application will be live at:
- Vercel: `https://threatsumm4ry.vercel.app`
- Netlify: `https://threatsumm4ry.netlify.app`
- Cloudflare: `https://threatsumm4ry.pages.dev`
- Self-hosted: `https://yourdomain.com`

Remember to update CORS settings on API vendors to allow your domain! 🚀
