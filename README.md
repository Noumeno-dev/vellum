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

## Learning and Documentation

Vellum is designed to be self-documenting. Once the platform is running, you can access comprehensive guides directly within the web interface regarding the configuration of OIDC and other OAuth2 providers.

If you wish to explore the documentation without installing the software, you can find the Markdown source files for various languages in the following directory:
`Vellum/web/public/docs`

These files provide a technical and functional deep dive into how Vellum helps you build a more reliable email infrastructure.

---

## License

MIT © Noumeno.dev

Vellum makes use of third-party dependencies. Full license texts (MIT, BSD-3-Clause, ISC, and Apache 2.0) are available at `THIRD_PARTY_LICENSES.md`.
