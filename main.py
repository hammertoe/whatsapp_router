# whatsapp_router_service.py
"""
Standalone WhatsApp Router Service
Routes WhatsApp messages based on Firestore rules to different bot endpoints.
"""

import os
import json
import logging
import threading
import requests
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from flask import Flask, request as flask_request, make_response, abort

# Try to import functions_framework, but don't fail if it's not available
try:
    import functions_framework
    HAS_FUNCTIONS_FRAMEWORK = True
except ImportError:
    print("⚠️  functions_framework not available - running in Flask-only mode")
    print("   This is fine for local development and Cloud Run deployment")
    HAS_FUNCTIONS_FRAMEWORK = False

# Google Cloud imports
from google.cloud import firestore

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    force=True
)
logger = logging.getLogger(__name__)

# Configuration from environment variables
PHONE_NUMBER_ID = os.getenv("PHONE_NUMBER_ID")
WABA_ACCESS_TOKEN = os.getenv("WABA_ACCESS_TOKEN") 
WHATSAPP_API_VERSION = os.getenv("WHATSAPP_API_VERSION", "v19.0")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN")
FIRESTORE_PROJECT = os.getenv("FIRESTORE_PROJECT")
FIRESTORE_DATABASE = os.getenv("FIRESTORE_DATABASE", "(default)")
ADMIN_SECRET = os.getenv("ADMIN_SECRET")  # New admin authentication secret

class RouteAction(Enum):
    """Actions that can be taken when routing a message."""
    FORWARD = "forward"  # Forward to another service
    HOLD = "hold"       # Send holding message
    BLOCK = "block"     # Block/ignore the message

@dataclass
class RoutingRule:
    """Defines how to route messages for specific users/patterns."""
    user_id: Optional[str] = None
    user_pattern: Optional[str] = None
    action: RouteAction = RouteAction.FORWARD
    target_url: Optional[str] = None
    hold_message: Optional[str] = None
    priority: int = 0

class WhatsAppClient:
    """WhatsApp client for sending messages and typing indicators."""
    
    def __init__(self, phone_number_id: str, access_token: str, api_version: str = "v19.0"):
        self.phone_number_id = phone_number_id
        self.access_token = access_token
        self.api_version = api_version
        self.base_url = f"https://graph.facebook.com/{api_version}"
        self.msg_endpoint = f"{self.base_url}/{phone_number_id}/messages"
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
    
    def send_text_message(self, to_number: str, text: str) -> bool:
        """Send a text message to a WhatsApp number."""
        payload = {
            "messaging_product": "whatsapp",
            "to": to_number,
            "type": "text",
            "text": {"body": text}
        }
        return self._send_request(payload, f"Message to {to_number}")
    
    def send_typing_indicator(self, msg_id: str) -> bool:
        """Send typing indicator for a message."""
        payload = {
            "messaging_product": "whatsapp",
            "status": "read",
            "message_id": msg_id,
            "typing_indicator": {"type": "text"}
        }
        return self._send_request(payload, f"Typing indicator for {msg_id}")
    
    def _send_request(self, payload: Dict[str, Any], operation: str) -> bool:
        """Common request sending logic."""
        try:
            response = requests.post(
                self.msg_endpoint,
                headers=self.headers,
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            logger.info(f"✓ {operation}")
            return True
        except Exception as e:
            logger.error(f"✗ {operation}: {e}")
            return False

class RoutingDatabase:
    """Firestore-based routing rule storage."""
    
    def __init__(self, project: Optional[str] = None, database: Optional[str] = None):
        self.db = firestore.Client(project=project, database=database)
        self.rules_collection = self.db.collection("whatsapp_routing_rules")
    
    def _add_rule_via_api(self, rule_data: Dict[str, Any]) -> None:
        """Add rule via API (internal method)."""
        try:
            action = RouteAction(rule_data.get('rule_action', 'hold').lower())
        except ValueError:
            raise ValueError(f"Invalid action: {rule_data.get('rule_action')}")
        
        rule = RoutingRule(
            user_id=rule_data.get('user_id'),
            user_pattern=rule_data.get('user_pattern'),
            action=action,
            target_url=rule_data.get('target_url'),
            hold_message=rule_data.get('hold_message'),
            priority=rule_data.get('priority', 0)
        )
        
        doc_id = rule.user_id or rule.user_pattern or f"pattern_{rule.priority}"
        rule_dict = rule.__dict__.copy()
        rule_dict['action'] = rule.action.value
        self.rules_collection.document(doc_id).set(rule_dict)
    
    def _remove_rule_via_api(self, identifier: str) -> None:
        """Remove rule via API (internal method)."""
        self.rules_collection.document(identifier).delete()
    
    def _set_default_rule_via_api(self, rule_data: Dict[str, Any]) -> None:
        """Set default rule via API (internal method)."""
        try:
            action = RouteAction(rule_data.get('rule_action', 'hold').lower())
        except ValueError:
            raise ValueError(f"Invalid action: {rule_data.get('rule_action')}")
        
        rule = RoutingRule(
            action=action,
            target_url=rule_data.get('target_url'),
            hold_message=rule_data.get('hold_message'),
            priority=0
        )
        
        rule_dict = rule.__dict__.copy()
        rule_dict['action'] = rule.action.value
        self.rules_collection.document("default").set(rule_dict)
    
    def get_all_rules(self) -> List[RoutingRule]:
        """Get all routing rules."""
        rules = []
        try:
            docs = self.rules_collection.get()
            for doc in docs:
                data = doc.to_dict()
                if data and 'action' in data:
                    data['action'] = RouteAction(data['action'])
                    rules.append(RoutingRule(**data))
            
            # Sort by priority (highest first)
            rules.sort(key=lambda r: r.priority, reverse=True)
            
        except Exception as e:
            logger.error(f"Error getting all routing rules: {e}")
            
        return rules
        
    def get_routing_rules(self, user_id: str) -> List[RoutingRule]:
        """Get routing rules for a specific user, sorted by priority."""
        rules = []
        
        try:
            # Get user-specific rules
            user_docs = self.rules_collection.where(filter=firestore.FieldFilter("user_id", "==", user_id)).get()
            for doc in user_docs:
                data = doc.to_dict()
                if 'action' in data:
                    data['action'] = RouteAction(data['action'])
                rules.append(RoutingRule(**data))
            
            # Get all documents and filter pattern-based rules in code
            # (Firestore doesn't support != None queries well)
            all_docs = self.rules_collection.get()
            for doc in all_docs:
                data = doc.to_dict()
                # Skip if this is the user-specific rule we already got
                if data.get('user_id') == user_id:
                    continue
                    
                # Check if this is a pattern-based rule
                if data.get('user_pattern') and data.get('user_pattern') != "":
                    if 'action' in data:
                        data['action'] = RouteAction(data['action'])
                    rule = RoutingRule(**data)
                    if self._matches_pattern(user_id, rule.user_pattern):
                        rules.append(rule)
            
            # Sort by priority (highest first)
            rules.sort(key=lambda r: r.priority, reverse=True)
            
        except Exception as e:
            logger.error(f"Error getting routing rules for {user_id}: {e}")
            
        return rules
    
    def get_default_routing_rule(self) -> RoutingRule:
        """Get the default routing rule."""
        try:
            doc = self.rules_collection.document("default").get()
            if doc.exists:
                data = doc.to_dict()
                if 'action' in data:
                    data['action'] = RouteAction(data['action'])
                return RoutingRule(**data)
        except Exception as e:
            logger.error(f"Error getting default routing rule: {e}")
            
        # Default fallback - hold with message
        logger.warning("No default routing rule found, using fallback hold message")
        return RoutingRule(
            action=RouteAction.HOLD,
            hold_message="Service temporarily unavailable. Please try again later."
        )
    
    def _matches_pattern(self, user_id: str, pattern: str) -> bool:
        """Simple pattern matching."""
        if pattern.endswith("*"):
            return user_id.startswith(pattern[:-1])
        return user_id == pattern

class MessageExtractor:
    """Extracts sender information from any WhatsApp message type."""
    
    @staticmethod
    def extract_sender(webhook_body: Dict[str, Any]) -> List[str]:
        """Extract all sender numbers from webhook body, regardless of message type."""
        senders = []
        
        try:
            changes = webhook_body.get("entry", [{}])[0].get("changes", [{}])[0]
            value = changes.get("value", {})
            messages = value.get("messages", [])
            
            for msg_data in messages:
                sender = msg_data.get("from")
                if sender:
                    senders.append(sender)
                    logger.debug(f"Extracted sender: {sender} from message type: {msg_data.get('type', 'unknown')}")
                else:
                    logger.warning("Message without 'from' field found")
                    
        except Exception as e:
            logger.error(f"Error extracting senders from webhook: {e}")
            
        return senders

class WhatsAppRouter:
    """Main router that processes and routes WhatsApp messages."""
    
    def __init__(self):
        # Check required configurations
        required_configs = [PHONE_NUMBER_ID, WABA_ACCESS_TOKEN, WHATSAPP_VERIFY_TOKEN]
        if any(config is None for config in required_configs):
            raise ValueError("Missing required WhatsApp configuration")
        
        self.whatsapp_client = WhatsAppClient(
            phone_number_id=PHONE_NUMBER_ID,
            access_token=WABA_ACCESS_TOKEN,
            api_version=WHATSAPP_API_VERSION
        )
        
        self.routing_db = RoutingDatabase(
            project=FIRESTORE_PROJECT,
            database=FIRESTORE_DATABASE
        )
        
        logger.info("WhatsApp Router initialized successfully")
    
    def verify_webhook(self, verify_token: str, challenge: str) -> tuple[bool, str]:
        """Verify WhatsApp webhook token."""
        if verify_token == WHATSAPP_VERIFY_TOKEN:
            logger.info("WhatsApp webhook verified successfully")
            return True, challenge
        else:
            logger.warning(f"Invalid verification token: {verify_token}")
            return False, "Invalid verification token"
    
    def verify_admin_access(self, provided_secret: str) -> bool:
        """Verify admin access using shared secret."""
        if not ADMIN_SECRET:
            logger.warning("ADMIN_SECRET not configured - admin access denied")
            return False
        
        if provided_secret == ADMIN_SECRET:
            logger.info("Admin access granted")
            return True
        else:
            logger.warning("Invalid admin secret provided")
            return False
    
    def process_webhook(self, body: Dict[str, Any]) -> str:
        """Process incoming webhook and route messages."""
        senders = MessageExtractor.extract_sender(body)
        
        if not senders:
            logger.debug("No senders found in webhook body")
            return "OK_NO_SENDERS"
        
        # Process each unique sender
        unique_senders = list(set(senders))
        for sender in unique_senders:
            # Start processing in separate thread for immediate response
            thread = threading.Thread(
                target=self._route_message,
                args=(sender, body)
            )
            thread.daemon = True
            thread.start()
            logger.info(f"Routing thread started for sender {sender}")
        
        return "OK_MESSAGES_ROUTED"
    
    def _route_message(self, sender: str, webhook_body: Dict[str, Any]) -> None:
        """Route a message based on sender and routing rules."""
        try:
            # Send typing indicator first (extract message ID if available)
            self._send_typing_indicator_if_possible(webhook_body)
            
            # Get routing rules for this sender
            rules = self.routing_db.get_routing_rules(sender)
            if not rules:
                rules = [self.routing_db.get_default_routing_rule()]
            
            # Apply the first (highest priority) rule
            rule = rules[0]
            logger.info(f"Applying rule for {sender}: {rule.action.value}")
            
            if rule.action == RouteAction.FORWARD:
                self._forward_message(sender, webhook_body, rule.target_url)
                
            elif rule.action == RouteAction.HOLD:
                hold_msg = rule.hold_message or "Service temporarily unavailable. Please try again later."
                self.whatsapp_client.send_text_message(sender, hold_msg)
                logger.info(f"Sent hold message to {sender}")
                
            elif rule.action == RouteAction.BLOCK:
                logger.info(f"Blocked message from {sender}")
                
        except Exception as e:
            logger.error(f"Error routing message from {sender}: {e}", exc_info=True)
            # Send error message to user
            self.whatsapp_client.send_text_message(
                sender,
                "Service temporarily unavailable. Please try again later."
            )
    
    def _send_typing_indicator_if_possible(self, webhook_body: Dict[str, Any]) -> None:
        """Send typing indicator if we can extract a message ID."""
        try:
            changes = webhook_body.get("entry", [{}])[0].get("changes", [{}])[0]
            value = changes.get("value", {})
            messages = value.get("messages", [])
            
            for msg_data in messages:
                message_id = msg_data.get("id")
                if message_id:
                    self.whatsapp_client.send_typing_indicator(message_id)
                    break  # Only send for first message
                    
        except Exception as e:
            logger.debug(f"Could not send typing indicator: {e}")
    
    def _forward_message(self, sender: str, webhook_body: Dict[str, Any], target_url: Optional[str]) -> None:
        """Forward message to target URL."""
        if not target_url:
            logger.error(f"No target URL for forwarding message from {sender}")
            self.whatsapp_client.send_text_message(
                sender,
                "Service configuration error. Please contact support."
            )
            return
        
        try:
            # Forward the entire webhook body as-is
            response = requests.post(
                target_url,
                json=webhook_body,
                timeout=30,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully forwarded message from {sender} to {target_url}")
            else:
                logger.error(f"Failed to forward message from {sender}: {response.status_code} {response.text}")
                self.whatsapp_client.send_text_message(
                    sender,
                    "Service temporarily unavailable. Please try again later."
                )
                
        except Exception as e:
            logger.error(f"Error forwarding message from {sender}: {e}")
            self.whatsapp_client.send_text_message(
                sender,
                "Service temporarily unavailable. Please try again later."
            )

# Global router instance
router = None

try:
    router = WhatsAppRouter()
except Exception as e:
    logger.critical(f"Failed to initialize WhatsApp Router: {e}")

# Define the main handler function that works with or without functions_framework
def main_handler(request_obj: flask_request):
    """Main HTTP handler for Google Cloud Functions or Flask."""
    if not router:
        return abort(500, "Router not initialized")
    
    path = request_obj.path
    method = request_obj.method

    # Health check endpoint
    if path == "/" and method == "GET":
        return make_response({
            "service": "WhatsApp Router",
            "status": "healthy",
            "version": "1.0.0"
        }, 200)

    # WhatsApp webhook endpoint
    elif path == "/webhook/whatsapp":
        if method == "GET":
            # Webhook verification
            verify_token = request_obj.args.get("hub.verify_token")
            challenge = request_obj.args.get("hub.challenge")
            
            if not verify_token or not challenge:
                return abort(400, "Missing verification parameters")
            
            is_valid, response = router.verify_webhook(verify_token, challenge)
            return make_response(response, 200 if is_valid else 403)

        elif method == "POST":
            try:
                body = request_obj.get_json(silent=True) or {}
                response_message = router.process_webhook(body)
                return make_response(response_message, 200)
                
            except Exception as e:
                logger.error(f"Error processing webhook: {e}", exc_info=True)
                return make_response("OK_ERROR_PROCESSING", 200)
        
        else:
            return abort(405, f"Method {method} not allowed")

    # Admin endpoint to check routing rules
    elif path == "/admin/rules" and method == "GET":
        # Check admin authentication
        auth_header = request_obj.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return abort(401, "Missing or invalid Authorization header. Use: Authorization: Bearer <secret>")
        
        provided_secret = auth_header.replace('Bearer ', '')
        if not router.verify_admin_access(provided_secret):
            return abort(403, "Invalid admin secret")
        
        try:
            user_id = request_obj.args.get("user_id")
            
            if user_id:
                # Get rules for specific user
                rules = router.routing_db.get_routing_rules(user_id)
                rules_data = []
                for rule in rules:
                    rules_data.append({
                        "user_id": rule.user_id,
                        "user_pattern": rule.user_pattern,
                        "action": rule.action.value,
                        "target_url": rule.target_url,
                        "hold_message": rule.hold_message,
                        "priority": rule.priority
                    })
                return make_response({"user_id": user_id, "rules": rules_data}, 200)
            else:
                # Get all rules
                all_rules = router.routing_db.get_all_rules()
                rules_data = []
                for rule in all_rules:
                    rules_data.append({
                        "user_id": rule.user_id,
                        "user_pattern": rule.user_pattern,
                        "action": rule.action.value,
                        "target_url": rule.target_url,
                        "hold_message": rule.hold_message,
                        "priority": rule.priority
                    })
                return make_response({"rules": rules_data}, 200)
            
        except Exception as e:
            logger.error(f"Error retrieving rules: {e}", exc_info=True)
            return abort(500, "Error retrieving rules")

    # Admin endpoint to manage rules via API
    elif path == "/admin/rules" and method == "POST":
        # Check admin authentication
        auth_header = request_obj.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return abort(401, "Missing or invalid Authorization header. Use: Authorization: Bearer <secret>")
        
        provided_secret = auth_header.replace('Bearer ', '')
        if not router.verify_admin_access(provided_secret):
            return abort(403, "Invalid admin secret")
        
        try:
            body = request_obj.get_json(silent=True) or {}
            action = body.get('action')
            
            if action == 'add_rule':
                router.routing_db._add_rule_via_api(body)
                return make_response({"status": "success", "message": "Rule added"}, 200)
            elif action == 'remove_rule':
                identifier = body.get('identifier')
                if identifier:
                    router.routing_db._remove_rule_via_api(identifier)
                    return make_response({"status": "success", "message": "Rule removed"}, 200)
                else:
                    return abort(400, "identifier required for remove_rule")
            elif action == 'set_default':
                router.routing_db._set_default_rule_via_api(body)
                return make_response({"status": "success", "message": "Default rule set"}, 200)
            else:
                return abort(400, "Invalid action. Use: add_rule, remove_rule, or set_default")
                
        except Exception as e:
            logger.error(f"Error managing rules via API: {e}", exc_info=True)
            return abort(500, "Error managing rules")
            
    else:
        return abort(404, f"Path {path} not found")

# Register with functions_framework if available
if HAS_FUNCTIONS_FRAMEWORK:
    @functions_framework.http
    def cloud_function_handler(request):
        """Entry point for Google Cloud Functions."""
        return main_handler(request)

# For local testing
if __name__ == "__main__":
    app = Flask(__name__)
    
    # Check required configurations
    required_configs = [
        ("PHONE_NUMBER_ID", PHONE_NUMBER_ID),
        ("WABA_ACCESS_TOKEN", WABA_ACCESS_TOKEN),
        ("WHATSAPP_VERIFY_TOKEN", WHATSAPP_VERIFY_TOKEN)
    ]
    
    missing_configs = [name for name, value in required_configs if not value]
    
    if missing_configs:
        print("❌ CRITICAL: Missing required configurations:")
        for config in missing_configs:
            print(f"   - {config}")
        print("Router will not function correctly.")
    else:
        print("✅ All required configurations present")
    
    if not ADMIN_SECRET:
        print("⚠️  WARNING: ADMIN_SECRET not set - admin endpoints will be disabled")
    else:
        print("✅ Admin authentication configured")
    
    if not router:
        print("❌ CRITICAL: WhatsApp Router NOT INITIALIZED.")
    else:
        print("✅ WhatsApp Router initialized and ready")

    @app.route("/", methods=["GET"])
    def health():
        return main_handler(flask_request)

    @app.route("/webhook/whatsapp", methods=["GET", "POST"])
    def webhook():
        return main_handler(flask_request)
    
    @app.route("/admin/rules", methods=["GET", "POST"])
    def admin():
        return main_handler(flask_request)
    
    port = int(os.getenv("PORT", 8080))
    print(f"\n🚀 Starting WhatsApp Router Service on port {port}")
    print(f"   Health check: http://0.0.0.0:{port}/")
    print(f"   Webhook: http://0.0.0.0:{port}/webhook/whatsapp")
    print(f"   Admin: http://0.0.0.0:{port}/admin/rules?user_id=<user_id>")
    print("\n📋 Required Environment Variables:")
    print("   PHONE_NUMBER_ID")
    print("   WABA_ACCESS_TOKEN") 
    print("   WHATSAPP_VERIFY_TOKEN")
    print("   ADMIN_SECRET (for admin endpoints)")
    print("   FIRESTORE_PROJECT (optional)")
    print("   FIRESTORE_DATABASE (optional, defaults to '(default)')")
    
    if HAS_FUNCTIONS_FRAMEWORK:
        print("✅ Functions Framework available - compatible with Cloud Functions")
    else:
        print("⚠️  Functions Framework not available - Flask-only mode")
        print("   Still compatible with Cloud Run and local development")
    
    app.run(host="0.0.0.0", port=port, debug=True)