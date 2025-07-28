# 🔥 Advanced XSS Vulnerability Lab

A cutting-edge Cross-Site Scripting (XSS) learning platform with 10 progressively challenging levels, real-world scenarios, and modern bypass techniques.

### 🎯 Comprehensive XSS Challenges
- **10 Progressive Levels** from basic to advanced
- **Multiple XSS Types**:
  - Reflected, Stored, DOM-based
  - SVG, Template Literals, AngularJS
  - WebSocket, Service Worker
- **Real-world filters** and WAF bypass techniques

### 🛠️ Learning Tools
- Interactive comment system for stored XSS
- DOM-based XSS playground
- WebSocket injection simulator
- Comprehensive cheat sheet with payloads
- Hint system for each challenge

### 🎨 Professional UI
- Modern responsive design
- Dark/light mode ready
- Animated progress tracking
- Challenge completion system

## 🚀 Getting Started

### Prerequisites
- Python 3.7+
- pip

### Installation
1. Clone the repository:
```
git clone https://github.com/Epic-Destroye-Op/Advanced-Xss-Lab.git
cd Advanced-Xss-Lab
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```
python app.py
```

4. Access the lab at:
```
http://localhost:5000 or http://yourip:5000
```

### Default Credentials
| Role     | Username | Password   |
|----------|----------|------------|
| Admin    | admin    | Admin@123  |
| Student  | student  | Student@123|

## 🧪 Challenge Roadmap

| Level | Type               | Key Technique                     | Difficulty |
|-------|--------------------|-----------------------------------|------------|
| 1     | Basic Reflected    | `<script>` tags                   | ★☆☆☆☆      |
| 2     | HTML Escape        | Event handlers                    | ★★☆☆☆      |
| 3     | Attribute Context  | JavaScript URIs                   | ★★☆☆☆      |
| 4     | DOM-based          | Fragment identifiers              | ★★★☆☆      |
| 5     | SVG Injection      | SVG event handlers                | ★★★☆☆      |
| 6     | Template Literals  | String concatenation              | ★★★★☆      |
| 7     | WAF Bypass         | Mixed-case/encoding               | ★★★★☆      |
| 8     | Service Worker     | Cache poisoning                   | ★★★★★      |
| 9     | AngularJS          | Prototype pollution               | ★★★★★      |
| 10    | WebSocket          | Real-time injection               | ★★★★★      |

## 🛡️ Security Note

⚠️ **This lab contains real vulnerabilities for educational purposes only**
- Run only in controlled environments
- Never expose to untrusted networks
- Reset database regularly during testing

## 📚 Learning Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Documentation](https://portswigger.net/web-security/cross-site-scripting)
- [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

## 🛠️ Development

### Project Structure
```
advanced-xss-lab/
├── app.py                 # Main application
├── requirements.txt       # Dependencies
├── xsslab.db              # Database (auto-created)
└── templates/             # HTML templates
    ├── base.html          # Base template
    ├── home.html          # Landing page
    ├── dashboard.html     # Challenge dashboard
    ├── level.html         # Individual challenges
    ├── comments.html      # Stored XSS system
    ├── dom.html           # DOM XSS playground
    ├── websocket.html     # WebSocket demo  
    ├── playground.html    # XSS testing ground
    └── cheatsheet.html    # Payload reference
```

---.
                                           **made by EpicDestroyerOp**
