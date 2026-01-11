# JSCollector - Burp Suite Extension

Passively collects **Secrets & Paths/URLs** from JavaScript files proxied through Burp Suite. Supports **custom regex patterns and categories**.


https://github.com/user-attachments/assets/aeaf762f-14f7-4dd5-9c35-f9e4ac2359cc


## Features

- **Passive Collection** - Auto-analyzes JS responses through proxy
- **Secret Scanning** - AWS, Google, Stripe, GitHub, Slack, JWT, database URIs, etc.
- **Endpoint Detection** - API paths, REST endpoints, OAuth, admin routes
- **URL Extraction** - Full URLs including cloud storage (S3, Azure, GCP)

## Installation

1. Download [Jython standalone JAR](https://www.jython.org/download)
2. In Burp: `Extensions > Extensions-Settings > Python Environment` → Set Jython path
3. `Extensions > Installed > Add` → Select `Python` → Browse to `jscollector.py`
4. Voilla! now you can browse normally while jscollector working automatically in the background collecting juicy stuff.

## Usage

### Passive Mode (Default)

- Browse websites through Burp proxy
- JS files are automatically analyzed
- Results appear in **JSCollector** tab

### Manual Mode

- Right-click any response in Proxy/Target/Repeater
- Select **"Analyze JS with JSCollector"**

### Custom Patterns

1. Click **Settings** in JSCollector tab
2. Add regex pattern with category and name
3. Optionally create custom categories

## License

MIT License
