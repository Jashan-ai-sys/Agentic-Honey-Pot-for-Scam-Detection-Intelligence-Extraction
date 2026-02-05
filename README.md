# Agentic Honey-Pot API 🍯

Scam Detection & Intelligence Extraction API for GUVI Hackathon

## Features

- ✅ **Scam Detection** - Keyword-based detection of scam messages
- ✅ **Agent Persona** - Human-like responses that engage scammers
- ✅ **Intelligence Extraction** - Captures UPI IDs, URLs, phone numbers, keywords
- ✅ **GUVI Callback** - Automatic reporting to GUVI endpoint
- ✅ **API Key Auth** - Secure endpoint with x-api-key header

## Quick Start

### 1. Install Dependencies

```bash
python -m venv venv
.\venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and set your API_KEY
```

### 3. Run Locally

```bash
uvicorn main:app --reload --port 8000
```

### 4. Test the API

```bash
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: guvi-honeypot-x7k9m2p4q8r1" \
  -H "Content-Type: application/json" \
  -d '{"sessionId": "test1", "message": {"text": "Your account has been blocked"}}'
```

## API Endpoints

### POST /honeypot

Main endpoint for scam detection.

**Headers:**
- `x-api-key`: Your API key
- `Content-Type`: application/json

**Request Body:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "text": "Scammer's message here"
  },
  "conversationHistory": []
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Human-like response"
}
```

### GET /health

Health check endpoint.

## Deployment to Render

1. Push to GitHub
2. Connect repo to Render
3. Set environment variable: `API_KEY=your-secret-key`
4. Deploy!

## Your API Key

```
guvi-honeypot-x7k9m2p4q8r1
```

Use this key in Render environment variables and for GUVI submission.

## License

MIT
