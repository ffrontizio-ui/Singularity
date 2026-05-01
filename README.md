# Singularity Onion Platform

Singularity is a privacy-focused, microblogging platform designed for the Tor Network. It emphasizes a stateless architecture, minimal JavaScript, and secure communication.

## Features

- **Anonymous Posting**: Post anonymously without account registration.
- **Proof-of-Work (PoW)**: Anti-spam protection using SHA-256 challenges.
- **Darknet Directory**: Automatic tracking and status verification of Onion services.
- **Privacy First**: Designed to run cleanly within the Tor Browser with minimal JS.
- **Self-Destructing Posts**: Optional logic for ephemeral content.
- **Bitcoin Integration**: HD Wallet support for privacy-preserving payments.

## Tech Stack

- **Backend**: Python (Flask/FastAPI)
- **Database**: SQLite (Migratable to PostgreSQL)
- **Containerization**: Docker & Docker Compose
- **Network**: Integrated Tor Proxy support

## Getting Started

### Prerequisites

- Python 3.9+ 
- Docker (optional, for full environment)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ffrontizio-ui/Singularity-dev.git
   cd Singularity-dev
   ```

2. Set up environment variables:
   Copy `.env.example` to `.env` and configure accordingly.

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python main.py
   ```

## Development and Deployment

The project includes a `Dockerfile` and `docker-compose.yml` for easy deployment.

```bash
docker-compose up --build
```

## Security

Singularity is designed with privacy in mind. Always ensure your `.env` file and `.db` files are kept private and never committed to source control.

---
*Created with focus on privacy and decentralization.*
