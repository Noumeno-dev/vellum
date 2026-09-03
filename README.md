![Gemini_Generated_Image_uym7pbuym7pbuym7 (3)](https://github.com/user-attachments/assets/e72ed23a-1dcf-45db-b5c6-2bc74085033c)

# Vellum

Vellum is a specialized SMTP testing server and web interface designed for modern engineering teams. It serves as a secure sanctuary for development and staging environments, ensuring that sensitive dummy data remains strictly internal while providing developers with the tools to master the art of email delivery.

---

## Philosophy

The core of Vellum is built on three fundamental pillars:

- **Security through Isolation**: We believe that development data, even if it is "dummy" or "test" data, should be treated with the highest security standards. Vellum ensures that no email ever leaves your infrastructure, protecting your staging data from accidental leaks to the public internet.
- **The Insignia of Quality**: Vellum is more than a tool; it is a guide. By using our verification models, developers learn to build better, cleaner, and more professional emails that respect industry standards.
- **Efficiency for Teams**: Designed for collaborative environments, Vellum provides role-based access and project isolation, allowing multiple teams to work on the same instance without data cross-contamination.

---

## Verification Models

Vellum incorporates advanced logic to analyze your outgoing communications without taxing your infrastructure. These models run in milliseconds with negligible CPU and RAM impact, ensuring a high-performance developer experience.

### Vellum Verified

This model serves as a health and positivity check for your emails. It focuses on technical integrity, deliverability metrics, and structural health. Vellum Verified ensures that your application is generating "healthy" emails, checking headers and HTML standards to guarantee they would be well-received by real-world providers.

### Sentinel Verified

Our specialized analysis engine focused on content security and spam prevention. Sentinel analyzes patterns and triggers to identify potential red flags in your message body. It serves as a pedagogical tool for developers to understand why their automated emails might be flagged as spam or rejected by filters before they ever reach a production environment.

---

## Core Features

- **Project Isolation**: Route emails based on sender addresses into dedicated project inboxes.
- **Unified Auth**: Native support for OIDC, GitHub, Google, Discord, and secure local invitation systems.
- **Zero-Dependency Storage**: Powered by a robust BBolt database. Your entire environment lives in a single, portable file.
- **Real-Time Analysis**: Instant visual feedback on email content, attachments, and technical headers.
- **Security Guardrails**: Includes Token Family protection against session hijacking and HTTP-only cookie enforcement.

---

## Quick Start

### Repository and Images

- [GitHub Repository](https://github.com/Gerbo67/vellum)
- **Docker Hub**: `docker.io/gerbo67/vellum:latest`
- **GitHub Container Registry**: `ghcr.io/gerbo67/vellum:latest`

### Deployment with Docker Compose

Use the following configuration to deploy Vellum using our official pre-built image.

**Note on Authentication**: All external identity providers (OIDC, GitHub, Google, and Discord) are configured by the administrator directly within the application's settings panel after the initial setup.

```yaml
services:
  vellum:
    image: docker.io/gerbo67/vellum:latest  # Or use ghcr.io/gerbo67/vellum:latest
    pull_policy: always
    container_name: vellum
    restart: unless-stopped
    ports:
      - "8025:8025"  # Web Interface
      - "2525:2525"  # SMTP Port
    volumes:
      - vellum_data:/data
    pull_policy: always # Always pull latest image updates
    environment:
      VELLUM_PORT: 8025
      VELLUM_SMTP_PORT: 2525
      VELLUM_DB_PATH: /data/vellum.db
      VELLUM_BASE_URL: http://localhost:8025
      VELLUM_MAX_EMAIL_SIZE: 26214400
      VELLUM_JWT_SECRET: "" # Leave empty to auto-generate or set a static string
      # Log configuration
      LOG_LEVEL: info # debug | info | warn | error
      LOG_FORMAT: text # text | json

volumes:
  vellum_data:
    driver: local
```

---

### Connecting Your Application (SMTP Settings)

Point your application, staging server, or local environment to Vellum using the following SMTP parameters:

| Parameter | Value | Description |
| :--- | :--- | :--- |
| **Host** | `localhost` (or your Docker host IP / domain) | Address where Vellum is running |
| **Port** | `2525` | Default SMTP port (or whatever you mapped) |
| **Authentication** | None / Optional | Any username and password will be accepted |
| **Encryption / TLS** | None (Plain) or STARTTLS | No TLS certificate setup required for dev/test |

#### How Project Routing Works (`Senders`)

Vellum isolates emails by project using the sender address (`From:`):

1. **Create a Project**: In the Vellum web dashboard, click **New Project** (e.g. *"Acme App"*).
2. **Assign Senders**: In the **Senders** field, enter the addresses your application sends from, separated by commas (e.g. `notifications@acme.local, billing@acme.local`).
   > 💡 **Tip:** You do not need to own or configure DNS for these domains. Any fictional or real domain (e.g. `@acme.local`, `@company.test`, `@myapp.com`) works out of the box.
3. **Send from your Code**: Set your mail client's `From:` address to one of the registered project senders.
4. **Recipients (`To:`, `Cc:`, `Bcc:`)**: Can be literally any destination (e.g. `client@gmail.com`, `qa-test@random.org`). Vellum intercepts all outbound traffic safely.

#### Example Configuration in Applications

**Environment Variables (.env)**
```env
SMTP_HOST=localhost
SMTP_PORT=2525
SMTP_USER=
SMTP_PASSWORD=
MAIL_FROM_ADDRESS=notifications@acme.local
MAIL_FROM_NAME="Acme Platform"
```

**Node.js (Nodemailer)**
```javascript
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "localhost",
  port: 2525,
  secure: false, // TLS is not required
});

await transporter.sendMail({
  from: '"Acme App" <notifications@acme.local>', // Must match a registered Project Sender
  to: "customer@example.com",                    // Any recipient
  subject: "Account Confirmation",
  text: "Welcome to Acme App! Confirm your account: https://acme.local/verify",
  html: "<h1>Welcome!</h1><p>Confirm your account by clicking the link.</p>",
});
```

**Python**
```python
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg.set_content("Hello from Python testing Vellum!")
msg["Subject"] = "Test Notification"
msg["From"] = "notifications@acme.local"  # Must match a Project Sender
msg["To"] = "anyone@example.com"          # Any recipient

with smtplib.SMTP("localhost", 2525) as server:
    server.send_message(msg)
```

**C# (.NET / MailKit)**
```csharp
using MailKit.Net.Smtp;
using MimeKit;

var message = new MimeMessage();
message.From.Add(new MailboxAddress("Acme App", "notifications@acme.local"));
message.To.Add(new MailboxAddress("Test User", "user@example.com"));
message.Subject = "Vellum Verification Test";
message.Body = new TextPart("plain") { Text = "Testing email capture in Vellum." };

using var client = new SmtpClient();
await client.ConnectAsync("localhost", 2525, false);
await client.SendAsync(message);
await client.DisconnectAsync(true);
```


---

## Learning and Documentation

Vellum is designed to be self-documenting. Once the platform is running, you can access comprehensive guides directly within the web interface regarding the configuration of OIDC and other OAuth2 providers.

If you wish to explore the documentation without installing the software, you can find the Markdown source files for various languages in the following directory:
`Vellum/web/public/docs`

These files provide a technical and functional deep dive into how Vellum helps you build a more reliable email infrastructure.

---

## License

MIT © Noumeno.dev

Vellum makes use of third-party dependencies. Full license texts (MIT, BSD-3-Clause, ISC, and Apache 2.0) are available at `THIRD_PARTY_LICENSES.md`.
