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
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
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
# PYDANTIC MODELS
# =============================================================================

class Message(BaseModel):
    text: str
    role: Optional[str] = None
    timestamp: Optional[str] = None


class ConversationHistoryItem(BaseModel):
    role: Optional[str] = None
    text: str


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[ConversationHistoryItem]] = Field(default_factory=list)
    metadata: Optional[dict] = None


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

# Tracks session data: {sessionId: {"message_count": int, "intel": ExtractedIntelligence, "callback_sent": bool}}
session_store: dict = {}


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
    # Filter out email-like patterns (those with common email domains)
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
    # Filter out phone numbers from bank accounts
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

# Response templates for different scenarios
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


def generate_persona_reply(message_text: str, history: List[ConversationHistoryItem], is_scam: bool) -> str:
    """
    Generate a human-like response that:
    - Sounds like a confused or cautious user
    - Asks clarifying questions
    - Never reveals scam detection
    - Varies based on conversation history
    """
    history_length = len(history) if history else 0
    
    if history_length == 0:
        # First message - be confused
        return random.choice(CONFUSED_RESPONSES)
    elif history_length == 1:
        # Second turn - ask for clarification
        return random.choice(CLARIFICATION_RESPONSES)
    elif history_length == 2:
        # Third turn - be cautious but cooperative
        return random.choice(CAUTIOUS_RESPONSES)
    else:
        # Subsequent turns - mix of cooperative and cautious
        all_responses = COOPERATIVE_BUT_CLUELESS_RESPONSES + CAUTIOUS_RESPONSES
        return random.choice(all_responses)


# =============================================================================
# CALLBACK LOGIC
# =============================================================================

async def send_callback(session_id: str, total_messages: int, intel: ExtractedIntelligence):
    """
    Send final intelligence to GUVI callback endpoint.
    This is fire-and-forget - we don't block the main response.
    """
    try:
        # Generate agent notes based on extracted intelligence
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
        # Log but don't fail - callback errors should not affect main response
        print(f"[CALLBACK ERROR] Session {session_id}: {str(e)}")


def should_send_callback(session_id: str, intel: ExtractedIntelligence) -> bool:
    """
    Determine if we should send the callback based on:
    - Scam is detected
    - AND (message count >= 3 OR intelligence was extracted)
    - AND callback hasn't been sent for this session yet
    """
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
    """Application lifespan handler."""
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

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# API KEY AUTHENTICATION
# =============================================================================

def verify_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    """Validate the API key from request header."""
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )
    return x_api_key


# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """Health check endpoint."""
    return {"status": "healthy", "service": "honeypot-api", "version": "1.0.0"}


@app.get("/health")
async def health():
    """Health check endpoint for monitoring."""
    return {"status": "healthy"}


@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Header(..., alias="x-api-key")
):
    """
    Main honeypot endpoint that processes scam messages.
    
    - Authenticates using x-api-key header
    - Detects scam intent from message
    - Generates human-like reply
    - Extracts intelligence (UPI, URLs, phones, keywords)
    - Sends callback when conditions are met
    - Always returns valid JSON response
    """
    try:
        # Validate API key
        if api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        session_id = request.sessionId
        message_text = request.message.text
        history = request.conversationHistory or []
        
        # Initialize or update session tracking
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
        reply = generate_persona_reply(message_text, history, is_scam)
        
        # Check if callback should be sent
        if is_scam and should_send_callback(session_id, merged_intel):
            session_store[session_id]["callback_sent"] = True
            total_messages = session_store[session_id]["message_count"]
            background_tasks.add_task(send_callback, session_id, total_messages, merged_intel)
        
        return HoneypotResponse(status="success", reply=reply)
    
    except HTTPException:
        # Re-raise HTTP exceptions (like 401)
        raise
    except Exception as e:
        # Log error but return safe response
        print(f"[ERROR] Session {request.sessionId if request else 'unknown'}: {str(e)}")
        return HoneypotResponse(
            status="success",
            reply="Can you please explain this in more detail?"
        )


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
