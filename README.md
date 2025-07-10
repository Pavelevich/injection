# Unicode Steganography Tool

![img.png](img.png)

A React-based educational tool for demonstrating Unicode steganography techniques using invisible characters. This project is designed for cybersecurity research and educational purposes.

## 🎯 Purpose

This tool demonstrates how invisible Unicode characters can be used to hide information within seemingly normal text. It's designed to help security researchers and students understand:

- Unicode steganography techniques
- Hidden character injection methods
- Text analysis and detection strategies
- Defensive security measures

## 🚀 Features

- **Multiple Unicode Character Sets**: Support for various invisible character types
- **Real-time Encoding/Decoding**: Instant hiding and extraction of hidden messages
- **Visual Analysis**: Toggle view to see invisible characters highlighted
- **Educational Payloads**: Pre-configured examples for learning purposes
- **Copy Functionality**: Easy copying of generated steganographic text
- **Extraction Verification**: Automatic validation of hidden message extraction

## 🛠️ Installation

### Prerequisites
- Node.js 16+
- npm or yarn

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/Pavelevich/injection.git
cd injection
```

2. Install dependencies:
```bash
npm install
```

3. Start development server:
```bash
npm start
```

4. Open http://localhost:3000 in your browser

### Production Build

```bash
npm run build
```

## 📋 Project Structure

```
src/
├── components/
│   └── UnicodeStegTool.js    # Main steganography component
├── App.js                    # Application entry point
├── App.css                   # Styling
├── index.js                  # React DOM render
└── index.css                 # Global styles
public/
├── index.html               # HTML template
└── manifest.json            # PWA manifest
```

## 🔧 How It Works

### Encoding Process
1. Convert hidden message to binary (8-bit per character)
2. Map binary bits to invisible Unicode characters
3. Append encoded message to visible text
4. Add termination character

### Supported Unicode Character Sets
- **Zero-Width Characters**: ZWSP, ZWNJ, Invisible Separator
- **High Surrogate Pairs**: Characters that may show as ❓
- **Replacement Characters**: Designed to show as ❓
- **Invisible Math Operators**: Function Application, Invisible Times
- **Bi-Directional Controls**: LRM, RLM, PDF
- **Tag Characters**: Deprecated language tags
- **Invisible Separators**: Word joiners and separators

## 🎓 Educational Use Cases

### For Security Research
- Understanding steganographic attacks
- Developing detection mechanisms
- Testing input validation systems
- Training security awareness

### For Defensive Security
- Building content filters
- Creating detection algorithms
- Implementing input sanitization
- Security policy development

## ⚠️ Important Disclaimers

### Educational Purpose Only
- This tool is intended solely for educational and research purposes
- Do not use for malicious activities or unauthorized testing
- Always obtain proper authorization before testing on systems you don't own
- Respect all applicable laws and regulations

### Security Considerations
- Hidden messages can bypass basic content filters
- Always validate and sanitize user input in production systems
- Implement proper Unicode normalization in security-critical applications
- Monitor for unusual Unicode character patterns

## 🛡️ Defensive Measures

### Detection Strategies
```javascript
// Example: Detect suspicious Unicode characters
const suspiciousChars = ['\u200B', '\u200C', '\u2063'];
const hasSuspiciousChars = text => 
  text.split('').some(char => suspiciousChars.includes(char));
```

### Sanitization Approaches
- Strip invisible Unicode characters
- Normalize Unicode text (NFC, NFD)
- Implement character whitelisting
- Use content security policies

## 🚀 Deployment

### Vercel Deployment
1. Push code to GitHub repository
2. Connect repository to Vercel
3. Automatic deployment on push

### Manual Deployment
1. Run `npm run build`
2. Deploy `build/` directory to web server

## 🤝 Contributing

Contributions focused on educational value and defensive security are welcome:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/education-enhancement`)
3. Commit changes (`git commit -am 'Add educational feature'`)
4. Push to branch (`git push origin feature/education-enhancement`)
5. Create Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Pavel Chmirenko**
- Email: developer31f@gmail.com
- GitHub: [@Pavelevich](https://github.com/Pavelevich)

## 🔗 Related Resources

- [Unicode Standard](https://unicode.org/standard/standard.html)
- [OWASP Input Validation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/)
- [Unicode Security Considerations](https://unicode.org/reports/tr36/)

## 📊 Technical Specifications

- **React Version**: 18.2.0
- **Supported Browsers**: Modern browsers with Unicode support
- **Character Encoding**: UTF-8/UTF-16
- **Binary Encoding**: 8-bit per character

## 🔒 Security Research Context

This tool helps demonstrate why proper input validation is crucial:
- Text that appears harmless may contain hidden instructions
- Visual inspection alone is insufficient for security
- Automated detection mechanisms are necessary
- Defense-in-depth strategies are essential

---

**⚠️ Remember: With great power comes great responsibility. Use this knowledge to build better defenses, not to cause harm.**
