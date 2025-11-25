# ThreatSumm4ry 🛡️

> **Comprehensive Threat Intelligence Dashboard** - Aggregate security analysis from 23+ threat intelligence vendors in one unified interface.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![React](https://img.shields.io/badge/React-18.x-61DAFB.svg?logo=react)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg?logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-5.x-646CFF.svg?logo=vite)](https://vitejs.dev/)

![ThreatSumm4ry Dashboard](https://via.placeholder.com/800x400/0ea5e9/ffffff?text=ThreatSumm4ry+Dashboard)

## ✨ Features

- 🔍 **Multi-Vendor Analysis** - Query 23 threat intelligence vendors simultaneously
- 🎯 **Smart Query Detection** - Auto-detects IPs, domains, hashes, and URLs
- 🔧 **Vendor Filtering** - Customize which vendors to query with quick filters
- 🆓 **11 Free APIs** - No API keys required for basic threat intelligence
- 📋 **Copy Vendor Links** - Quickly share analysis URLs across vendors
- 💾 **Persistent Preferences** - Your vendor selections are saved automatically
- ⚡ **Real-Time Results** - Fast parallel API calls with loading states
- 🌐 **Geolocation & WHOIS** - IP geolocation and domain WHOIS data at the top

## 🚀 Supported Vendors

### Free Vendors (No API Key Required)
- ✅ IP Geolocation
- ✅ WHOIS
- ✅ AlienVault OTX
- ✅ URLhaus
- ✅ ThreatFox
- ✅ MalwareBazaar
- ✅ PhishTank
- ✅ Pulsedive
- ✅ ThreatCrowd
- ✅ CIRCL hashlookup
- ✅ PhishStats
- ✅ Ransomware.live

### Premium Vendors (API Key Required)
- 🔑 VirusTotal
- 🔑 AbuseIPDB
- 🔑 Shodan
- 🔑 Google Safe Browsing
- 🔑 Censys
- 🔑 BinaryEdge
- 🔑 GreyNoise
- 🔑 IPQualityScore
- 🔑 Hybrid Analysis
- 🔑 Criminal IP
- 🔑 MetaDefender

## 📋 Prerequisites

- **Node.js** 18.x or higher - [Install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating)
- **npm** or **yarn**
- (Optional) API keys for premium vendors

## 🛠️ Installation

```bash
# Clone the repository
git clone <YOUR_GIT_URL>
cd intel-vista-22

# Install dependencies
npm install

# Copy environment example
cp .env.example .env

# Add your API keys to .env (optional)
# Edit .env and add your keys
```

## 🔑 Environment Variables

Create a `.env` file in the root directory:

```env
# Free APIs (No keys needed - leave empty)
# IP Geolocation, WHOIS, AlienVault OTX, URLhaus, ThreatFox, 
# MalwareBazaar, PhishStats, Ransomware.live, CIRCL, PhishTank, 
# Pulsedive, ThreatCrowd

# Premium APIs (Add your keys)
VITE_VIRUSTOTAL_API_KEY=your_key_here
VITE_ABUSEIPDB_API_KEY=your_key_here
VITE_SHODAN_API_KEY=your_key_here
VITE_GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
VITE_CENSYS_API_ID=your_id_here
VITE_CENSYS_API_SECRET=your_secret_here
VITE_BINARYEDGE_API_KEY=your_key_here
VITE_GREYNOISE_API_KEY=your_key_here
VITE_IPQS_API_KEY=your_key_here
VITE_HYBRID_ANALYSIS_API_KEY=your_key_here
VITE_CRIMINALIP_API_KEY=your_key_here
VITE_METADEFENDER_API_KEY=your_key_here
```

> ⚠️ **Security Note:** Never commit your `.env` file to Git. It's already in `.gitignore`.

## 🏃 Running Locally

```bash
# Development mode with hot reload
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

## 🎯 Usage

1. **Enter a Query:**
   - IP address: `8.8.8.8`
   - Domain: `example.com`
   - Hash: `44d88612fea8a8f36de82e1278abb02f`
   - URL: `https://example.com`

2. **Filter Vendors (Optional):**
   - Click "Filter Vendors" button
   - Use quick filters: "Only Free" or "Only Paid"
   - Select/deselect individual vendors
   - Click "Apply"

3. **Analyze:**
   - Click "Analyze" to query all selected vendors
   - View results from each vendor in expandable cards
   - Click "Copy All Vendor Links" to share analysis URLs

## 📦 Tech Stack

- **Frontend Framework:** React 18
- **Build Tool:** Vite 5
- **Language:** TypeScript
- **Styling:** Tailwind CSS
- **UI Components:** shadcn/ui
- **State Management:** TanStack Query (React Query)
- **Icons:** Lucide React

## 🚢 Deployment

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment instructions.

### Quick Deploy Options:

**Vercel (Recommended):**
```bash
npm install -g vercel
npm run build
vercel --prod
```

**Netlify:**
```bash
npm install -g netlify-cli
netlify deploy --prod --dir=dist
```

**Docker:**
```bash
docker build -t threatsumm4ry .
docker run -d -p 8080:80 threatsumm4ry
```

**GitHub Pages:**
```bash
npm run deploy
```

## 🔐 Security

- ✅ API keys managed via environment variables
- ✅ XSS protection through React
- ✅ Input validation for queries
- ✅ CSP headers (when using Nginx)
- ✅ HTTPS enforced in production

For production deployments, consider using a backend proxy to hide API keys. See [server-example.js](./server-example.js).

## 📚 Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Comprehensive deployment guide
- [API_RESOURCES.md](./API_RESOURCES.md) - API vendor documentation
- [.env.example](./.env.example) - Environment variable template

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- All the amazing threat intelligence vendors who provide APIs
- [shadcn/ui](https://ui.shadcn.com/) for beautiful UI components
- [Lucide](https://lucide.dev/) for icons
- The open-source community

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**Made with ❤️ for the cybersecurity community**
