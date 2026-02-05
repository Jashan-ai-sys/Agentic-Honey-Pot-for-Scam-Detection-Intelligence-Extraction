"""
Agentic Honey-Pot API for Scam Detection & Intelligence Extraction
GUVI Hackathon Submission

A minimal, reliable FastAPI service that:
- Detects scam messages using keyword matching
- Engages scammers with a believable human persona
- Extracts intelligence (UPI IDs, URLs, phone numbers, keywords)
- Reports findings via callback to GUVI
"""

import os
import re
import random
import httpx
from typing import Optional, List, Any, Union
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# =============================================================================
# CONFIGURATION
# =============================================================================

API_KEY = os.getenv("API_KEY", "default-secret-key")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Scam detection keywords (case-insensitive matching)
SCAM_KEYWORDS = [
    "blocked", "suspended", "verify", "urgent", "kyc", "otp", "upi", "refund",
    "account", "expire", "bank", "limit", "update", "click", "link", "immediately",
    "action required", "security", "warning", "alert", "unauthorized", "transaction",
    "failed", "locked", "restricted", "confirm", "credentials", "password", "pin",
    "cvv", "card", "reward", "prize", "winner", "lottery", "cash", "transfer",
    "payment", "pending", "hold", "freeze", "debit", "credit", "loan", "emi"
]

# =============================================================================
# PYDANTIC MODELS (Flexible)
# =============================================================================

class HoneypotResponse(BaseModel):
    status: str = "success"
    reply: str


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


class CallbackPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str


# =============================================================================
# IN-MEMORY SESSION TRACKING (for callback decision)
# =============================================================================

session_store: dict = {}


# =============================================================================
# REQUEST PARSING (Flexible - handles multiple formats)
# =============================================================================

def parse_request_body(body: dict) -> tuple[str, str, list]:
    """
    Parse request body flexibly to handle different formats.
    Returns (session_id, message_text, conversation_history)
    
    Supports formats:
    1. {"sessionId": "...", "message": {"text": "..."}, "conversationHistory": [...]}
    2. {"sessionId": "...", "message": "...", "conversationHistory": [...]}
    3. {"session_id": "...", "text": "...", "history": [...]}
    4. {"sessionId": "...", "text": "..."}
    5. And more variations...
    """
    # Extract session ID (try multiple field names)
    session_id = (
        body.get("sessionId") or 
        body.get("session_id") or 
        body.get("session") or
        body.get("id") or
        "default-session"
    )
    
    # Extract message text (try multiple field names and structures)
    message = body.get("message")
    if isinstance(message, dict):
        message_text = message.get("text") or message.get("content") or message.get("body") or ""
    elif isinstance(message, str):
        message_text = message
    else:
        message_text = (
            body.get("text") or 
            body.get("content") or 
            body.get("body") or
            body.get("msg") or
            ""
        )
    
    # Extract conversation history
    history = (
        body.get("conversationHistory") or 
        body.get("conversation_history") or
        body.get("history") or
        body.get("messages") or
        []
    )
    
    return str(session_id), str(message_text), list(history) if history else []


# =============================================================================
# SCAM DETECTION
# =============================================================================

def detect_scam(text: str) -> tuple[bool, List[str]]:
    """
    Detect if the message contains scam indicators.
    Returns (is_scam, list_of_matched_keywords)
    """
    text_lower = text.lower()
    matched_keywords = []
    
    for keyword in SCAM_KEYWORDS:
        if keyword in text_lower:
            matched_keywords.append(keyword)
    
    is_scam = len(matched_keywords) > 0
    return is_scam, matched_keywords


# =============================================================================
# INTELLIGENCE EXTRACTION
# =============================================================================

def extract_intelligence(text: str, matched_keywords: List[str]) -> ExtractedIntelligence:
    """
    Extract scam intelligence from the message using regex patterns.
    """
    intel = ExtractedIntelligence()
    
    # Extract UPI IDs (format: username@bankcode)
    upi_pattern = r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,10}'
    upi_matches = re.findall(upi_pattern, text)
    # Filter out email-like patterns
    email_domains = ['gmail', 'yahoo', 'hotmail', 'outlook', 'mail', 'email']
    intel.upiIds = [upi for upi in upi_matches if not any(domain in upi.lower() for domain in email_domains)]
    
    # Extract URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    intel.phishingLinks = list(set(re.findall(url_pattern, text)))
    
    # Extract Indian phone numbers
    phone_pattern = r'(?:\+91[\s-]?)?[6-9]\d{9}'
    intel.phoneNumbers = list(set(re.findall(phone_pattern, text)))
    
    # Add matched suspicious keywords
    intel.suspiciousKeywords = list(set(matched_keywords))
    
    # Extract potential bank account numbers (10-18 digit numbers)
    bank_pattern = r'\b\d{10,18}\b'
    potential_accounts = re.findall(bank_pattern, text)
    intel.bankAccounts = [acc for acc in potential_accounts if acc not in intel.phoneNumbers]
    
    return intel


def merge_intelligence(existing: ExtractedIntelligence, new: ExtractedIntelligence) -> ExtractedIntelligence:
    """Merge new intelligence with existing, avoiding duplicates."""
    return ExtractedIntelligence(
        bankAccounts=list(set(existing.bankAccounts + new.bankAccounts)),
        upiIds=list(set(existing.upiIds + new.upiIds)),
        phishingLinks=list(set(existing.phishingLinks + new.phishingLinks)),
        phoneNumbers=list(set(existing.phoneNumbers + new.phoneNumbers)),
        suspiciousKeywords=list(set(existing.suspiciousKeywords + new.suspiciousKeywords))
    )


# =============================================================================
# AGENT PERSONA RESPONSES
# =============================================================================

CONFUSED_RESPONSES = [
    "I'm not sure I understand. Can you explain what you mean?",
    "Sorry, I didn't receive any notification about this. Which department are you from?",
    "I'm confused. My account seems to be working fine. What exactly is the issue?",
    "Can you please clarify? I haven't had any problems with my account.",
    "This is the first I'm hearing about this. Can you provide more details?",
    "I don't recall having any issues. Are you sure you have the right person?",
]

CAUTIOUS_RESPONSES = [
    "I'd prefer to verify this directly with my bank. What's your official reference number?",
    "Before I do anything, I need to confirm this is legitimate. What's your employee ID?",
    "Let me check with my bank first. What phone number can I use to verify?",
    "I'm a bit skeptical about this. Can you send me an official email from the bank?",
    "My bank usually sends SMS from a specific number. Can you confirm your identity?",
]

CLARIFICATION_RESPONSES = [
    "Which bank is this regarding exactly?",
    "What specific account are you referring to?",
    "When exactly was this supposed to have happened?",
    "Can you tell me the last 4 digits of the account you're referring to?",
    "What transaction are you referring to? I need more specifics.",
]

COOPERATIVE_BUT_CLUELESS_RESPONSES = [
    "Oh dear, that sounds serious. What should I do to fix this?",
    "I didn't know there was a problem. What information do you need from me?",
    "This is very concerning. Can you walk me through what happened?",
    "I want to resolve this. What steps should I take?",
    "Please help me understand. What do you need me to verify?",
]


def generate_persona_reply(message_text: str, history_length: int, is_scam: bool) -> str:
    """
    Generate a human-like response based on conversation stage.
    """
    if history_length == 0:
        return random.choice(CONFUSED_RESPONSES)
    elif history_length == 1:
        return random.choice(CLARIFICATION_RESPONSES)
    elif history_length == 2:
        return random.choice(CAUTIOUS_RESPONSES)
    else:
        all_responses = COOPERATIVE_BUT_CLUELESS_RESPONSES + CAUTIOUS_RESPONSES
        return random.choice(all_responses)


# =============================================================================
# CALLBACK LOGIC
# =============================================================================

async def send_callback(session_id: str, total_messages: int, intel: ExtractedIntelligence):
    """Send final intelligence to GUVI callback endpoint."""
    try:
        notes_parts = []
        if intel.phishingLinks:
            notes_parts.append(f"Detected {len(intel.phishingLinks)} phishing link(s)")
        if intel.upiIds:
            notes_parts.append(f"Captured {len(intel.upiIds)} UPI ID(s)")
        if intel.phoneNumbers:
            notes_parts.append(f"Captured {len(intel.phoneNumbers)} phone number(s)")
        if intel.suspiciousKeywords:
            notes_parts.append(f"Keywords used: {', '.join(intel.suspiciousKeywords[:5])}")
        
        agent_notes = ". ".join(notes_parts) if notes_parts else "Scam attempt detected through suspicious messaging patterns."
        
        payload = CallbackPayload(
            sessionId=session_id,
            scamDetected=True,
            totalMessagesExchanged=total_messages,
            extractedIntelligence=intel,
            agentNotes=agent_notes
        )
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                GUVI_CALLBACK_URL,
                json=payload.model_dump(),
                headers={"Content-Type": "application/json"}
            )
            print(f"[CALLBACK] Sent for session {session_id}: Status {response.status_code}")
    except Exception as e:
        print(f"[CALLBACK ERROR] Session {session_id}: {str(e)}")


def should_send_callback(session_id: str, intel: ExtractedIntelligence) -> bool:
    """Determine if callback should be sent."""
    session = session_store.get(session_id, {})
    
    if session.get("callback_sent", False):
        return False
    
    message_count = session.get("message_count", 1)
    has_intel = (
        len(intel.upiIds) > 0 or
        len(intel.phishingLinks) > 0 or
        len(intel.phoneNumbers) > 0 or
        len(intel.bankAccounts) > 0
    )
    
    return message_count >= 3 or has_intel


# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🍯 Honeypot API starting...")
    print(f"📍 Callback URL: {GUVI_CALLBACK_URL}")
    yield
    print("🍯 Honeypot API shutting down...")


app = FastAPI(
    title="Agentic Honey-Pot API",
    description="Scam Detection & Intelligence Extraction for GUVI Hackathon",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    return {"status": "healthy", "service": "honeypot-api", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/honeypot")
async def honeypot_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(None, alias="x-api-key")
):
    """
    Main honeypot endpoint - accepts flexible request formats.
    """
    try:
        # Validate API key
        if x_api_key != API_KEY:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=401, content={"status": "error", "detail": "Invalid API key"})
        
        # Parse request body flexibly
        try:
            body = await request.json()
        except:
            body = {}
        
        session_id, message_text, history = parse_request_body(body)
        
        # Handle empty message
        if not message_text:
            return {"status": "success", "reply": "Hello! How can I help you today?"}
        
        # Initialize or update session
        if session_id not in session_store:
            session_store[session_id] = {
                "message_count": 0,
                "intel": ExtractedIntelligence(),
                "callback_sent": False
            }
        
        session_store[session_id]["message_count"] += 1
        
        # Detect scam
        is_scam, matched_keywords = detect_scam(message_text)
        
        # Extract intelligence
        new_intel = extract_intelligence(message_text, matched_keywords)
        
        # Merge with existing session intelligence
        existing_intel = session_store[session_id]["intel"]
        merged_intel = merge_intelligence(existing_intel, new_intel)
        session_store[session_id]["intel"] = merged_intel
        
        # Generate persona reply
        history_length = len(history)
        reply = generate_persona_reply(message_text, history_length, is_scam)
        
        # Check if callback should be sent
        if is_scam and should_send_callback(session_id, merged_intel):
            session_store[session_id]["callback_sent"] = True
            total_messages = session_store[session_id]["message_count"]
            background_tasks.add_task(send_callback, session_id, total_messages, merged_intel)
        
        return {"status": "success", "reply": reply}
    
    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return {"status": "success", "reply": "Can you please explain this in more detail?"}


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
