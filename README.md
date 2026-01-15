# Security Validator
A web application to validate security vulnerabilities across multiple domains, specifically checking SSL certificate expiration and cookie security configurations.

## UI Preview

![Security Validator UI](./screenshots/dark_mode_layout_1768461705302.png)

## Features

- ✅ **SSL Certificate Validation**
  - Check certificate expiration dates
  - Calculate days until expiration
  - Severity levels (OK, Warning, Critical)
  - Detailed certificate information

- ✅ **Cookie Security Analysis**
  - Detect missing Secure flags
  - Check for HttpOnly attributes
  - Verify SameSite settings
  - Identify non-compliant cookies

- ✅ **Batch Processing**
  - Validate multiple domains simultaneously
  - Progress tracking
  - Real-time results display

- ✅ **Modern UI/UX**
  - Dark theme with glassmorphism
  - Smooth animations and transitions
  - Responsive design
  - Export results to JSON

## Installation

1. **Clone or navigate to the project directory:**
   ```bash
   cd Security-Validator
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

## Usage

1. **Start the server:**
   ```bash
   npm start
   ```

2. **Open your browser:**
   Navigate to `http://localhost:3000`

3. **Add domains:**
   - Enter domain names (e.g., `google.com` or `https://example.com`)
   - Click "Add Domain" or press Enter
   - Add as many domains as needed

4. **Validate:**
   - Click "Validate All Domains"
   - Wait for the validation to complete
   - Review the detailed results

5. **Export results:**
   - Click "Export Results (JSON)" to download the validation data

## API Endpoints

### Health Check
```
GET /api/health
```

### Check SSL Certificate
```
GET /api/check-ssl/:domain
```

### Check Cookie Security
```
GET /api/check-cookies/:domain
```

### Batch Validation
```
POST /api/validate
Body: { "domains": ["example.com", "google.com"] }
```

## Technology Stack

- **Backend:** Node.js, Express
- **Frontend:** Vanilla JavaScript, HTML5, CSS3
- **Dependencies:**
  - `express` - Web server framework
  - `cors` - Cross-origin resource sharing
  - `ssl-checker` - SSL certificate validation
  - `axios` - HTTP client
  - `helmet` - Security headers

## Configuration

Default port: `3000`

To change the port, set the `PORT` environment variable:
```bash
PORT=8080 npm start
```

## Security Checks

### SSL Certificate
- ✅ Days until expiration
- ✅ Certificate validity period
- ✅ Issuer information
- ✅ Automatic severity assessment

### Cookie Security
- ✅ Secure flag presence
- ✅ HttpOnly flag presence
- ✅ SameSite attribute
- ✅ Per-cookie issue reporting

## Browser Compatibility

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)

## License

MIT
