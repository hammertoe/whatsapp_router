# router_admin.py
"""
Administration tool for managing WhatsApp routing rules.
Standalone version for the router service.
"""

import argparse
import logging
import os
import requests
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from google.cloud import firestore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RouteAction(Enum):
    """Actions that can be taken when routing a message."""
    FORWARD = "forward"
    HOLD = "hold"
    BLOCK = "block"

@dataclass
class RoutingRule:
    """Defines how to route messages for specific users/patterns."""
    user_id: Optional[str] = None
    user_pattern: Optional[str] = None
    action: RouteAction = RouteAction.FORWARD
    target_url: Optional[str] = None
    hold_message: Optional[str] = None
    priority: int = 0

class RouterAdmin:
    """Admin interface for managing routing rules."""
    
    def __init__(self, project: Optional[str] = None, database: Optional[str] = None, 
                 use_api: bool = False, api_url: Optional[str] = None, admin_secret: Optional[str] = None):
        self.use_api = use_api
        self.api_url = api_url
        self.admin_secret = admin_secret
        
        if use_api:
            if not api_url:
                raise ValueError("api_url required when use_api=True")
            if not admin_secret:
                raise ValueError("admin_secret required when use_api=True")
            print(f"Using API mode: {api_url}")
            print("Admin secret configured")
        else:
            self.db = firestore.Client(project=project, database=database)
            self.rules_collection = self.db.collection("whatsapp_routing_rules")
            print(f"Connected to Firestore project: {project or 'default'}")
            print(f"Using database: {database or '(default)'}")
            print(f"Collection: whatsapp_routing_rules")
    
    def add_rule(
        self, 
        action: str,
        user_id: Optional[str] = None,
        user_pattern: Optional[str] = None,
        target_url: Optional[str] = None,
        hold_message: Optional[str] = None,
        priority: int = 0
    ):
        """Add a new routing rule."""
        try:
            route_action = RouteAction(action.lower())
        except ValueError:
            print(f"❌ Invalid action: {action}")
            print("   Valid actions: forward, hold, block")
            return
        
        if not user_id and not user_pattern:
            print("❌ Either --user-id or --user-pattern must be specified")
            return
        
        if route_action == RouteAction.FORWARD and not target_url:
            print("❌ --target-url is required for 'forward' action")
            return
        
        if self.use_api:
            self._add_rule_via_api(action, user_id, user_pattern, target_url, hold_message, priority)
        else:
            self._add_rule_direct(action, user_id, user_pattern, target_url, hold_message, priority)
    
    def _add_rule_via_api(self, action: str, user_id: Optional[str], user_pattern: Optional[str], 
                         target_url: Optional[str], hold_message: Optional[str], priority: int):
        """Add rule via API."""
        try:
            payload = {
                "action": "add_rule",
                "rule_action": action,
                "user_id": user_id,
                "user_pattern": user_pattern,
                "target_url": target_url,
                "hold_message": hold_message,
                "priority": priority
            }
            
            headers = {"Authorization": f"Bearer {self.admin_secret}"}
            response = requests.post(f"{self.api_url}/admin/rules", json=payload, headers=headers)
            
            if response.status_code == 200:
                print(f"✅ Added routing rule for {user_id or user_pattern}")
                print(f"   Action: {action}")
                if target_url:
                    print(f"   Target URL: {target_url}")
                if hold_message:
                    print(f"   Hold message: {hold_message}")
                print(f"   Priority: {priority}")
            else:
                print(f"❌ Failed to add rule: {response.status_code} {response.text}")
                
        except Exception as e:
            print(f"❌ Error adding rule via API: {e}")
    
    def _add_rule_direct(self, action: str, user_id: Optional[str], user_pattern: Optional[str], 
                        target_url: Optional[str], hold_message: Optional[str], priority: int):
        """Add rule directly to Firestore."""
        rule = RoutingRule(
            user_id=user_id,
            user_pattern=user_pattern,
            action=RouteAction(action.lower()),
            target_url=target_url,
            hold_message=hold_message,
            priority=priority
        )
        
        # Save to Firestore (convert enum to string for serialization)
        doc_id = user_id or user_pattern or f"pattern_{priority}"
        rule_data = rule.__dict__.copy()
        rule_data['action'] = rule.action.value
        
        self.rules_collection.document(doc_id).set(rule_data)
        
        print(f"✅ Added routing rule for {user_id or user_pattern}")
        print(f"   Action: {action}")
        if target_url:
            print(f"   Target URL: {target_url}")
        if hold_message:
            print(f"   Hold message: {hold_message}")
        print(f"   Priority: {priority}")
    
    def list_rules(self, user_id: Optional[str] = None):
        """List routing rules."""
        if self.use_api:
            self._list_rules_via_api(user_id)
        else:
            self._list_rules_direct(user_id)
    
    def _list_rules_via_api(self, user_id: Optional[str] = None):
        """List rules via API."""
        try:
            headers = {"Authorization": f"Bearer {self.admin_secret}"}
            
            if user_id:
                # Get rules for specific user
                response = requests.get(f"{self.api_url}/admin/rules?user_id={user_id}", headers=headers)
                title = f"📋 Routing rules for user {user_id}:"
                rules_key = 'rules'
            else:
                # Get all rules
                response = requests.get(f"{self.api_url}/admin/rules", headers=headers)
                title = f"📋 All routing rules:"
                rules_key = 'rules'
            
            if response.status_code == 200:
                data = response.json()
                rules = data.get(rules_key, [])
                print(f"\n{title}")
                
                if not rules:
                    print("   No rules found")
                    return
                
                for i, rule in enumerate(rules, 1):
                    print(f"\n   Rule {i}:")
                    print(f"     User ID: {rule.get('user_id') or 'N/A'}")
                    print(f"     User Pattern: {rule.get('user_pattern') or 'N/A'}")
                    print(f"     Action: {rule.get('action')}")
                    print(f"     Target URL: {rule.get('target_url') or 'N/A'}")
                    print(f"     Hold Message: {rule.get('hold_message') or 'N/A'}")
                    print(f"     Priority: {rule.get('priority')}")
            else:
                print(f"❌ Failed to list rules: {response.status_code} {response.text}")
                
        except Exception as e:
            print(f"❌ Error listing rules via API: {e}")
    
    def _list_rules_direct(self, user_id: Optional[str] = None):
        """List routing rules."""
        try:
            if user_id:
                print(f"\n📋 Routing rules for user {user_id}:")
                # Get user-specific rules
                user_docs = self.rules_collection.where(filter=firestore.FieldFilter("user_id", "==", user_id)).get()
                rules = []
                for doc in user_docs:
                    data = doc.to_dict()
                    if data and 'action' in data:
                        data['action'] = RouteAction(data['action'])
                        rules.append(RoutingRule(**data))
                
                # Get all docs and filter pattern-based rules in code
                all_docs = self.rules_collection.get()
                for doc in all_docs:
                    data = doc.to_dict()
                    # Skip if this is the user-specific rule we already got
                    if data.get('user_id') == user_id:
                        continue
                        
                    # Check if this is a pattern-based rule that matches
                    if data.get('user_pattern') and data.get('user_pattern') != "":
                        if 'action' in data:
                            data['action'] = RouteAction(data['action'])
                            rule = RoutingRule(**data)
                            if self._matches_pattern(user_id, rule.user_pattern):
                                rules.append(rule)
                
                # Sort by priority
                rules.sort(key=lambda r: r.priority, reverse=True)
            else:
                print(f"\n📋 All routing rules:")
                docs = self.rules_collection.get()
                rules = []
                for doc in docs:
                    data = doc.to_dict()
                    if data and 'action' in data:
                        data['action'] = RouteAction(data['action'])
                        rules.append((doc.id, RoutingRule(**data)))
                
                # Sort by priority
                rules.sort(key=lambda x: x[1].priority, reverse=True)
                rules = [rule for _, rule in rules]  # Remove doc IDs for display
            
            if not rules:
                print("   No rules found")
                return
            
            for i, rule in enumerate(rules, 1):
                print(f"\n   Rule {i}:")
                print(f"     User ID: {rule.user_id or 'N/A'}")
                print(f"     User Pattern: {rule.user_pattern or 'N/A'}")
                print(f"     Action: {rule.action.value}")
                print(f"     Target URL: {rule.target_url or 'N/A'}")
                print(f"     Hold Message: {rule.hold_message or 'N/A'}")
                print(f"     Priority: {rule.priority}")
                
        except Exception as e:
            print(f"❌ Error listing rules: {e}")
    
    def remove_rule(self, identifier: str):
        """Remove a routing rule by user_id or pattern."""
        if self.use_api:
            self._remove_rule_via_api(identifier)
        else:
            self._remove_rule_direct(identifier)
    
    def _remove_rule_via_api(self, identifier: str):
        """Remove rule via API."""
        try:
            payload = {"action": "remove_rule", "identifier": identifier}
            headers = {"Authorization": f"Bearer {self.admin_secret}"}
            response = requests.post(f"{self.api_url}/admin/rules", json=payload, headers=headers)
            
            if response.status_code == 200:
                print(f"✅ Removed routing rule for {identifier}")
            else:
                print(f"❌ Failed to remove rule: {response.status_code} {response.text}")
                
        except Exception as e:
            print(f"❌ Error removing rule via API: {e}")
    
    def _remove_rule_direct(self, identifier: str):
        """Remove rule directly from Firestore."""
        try:
            doc_ref = self.rules_collection.document(identifier)
            doc = doc_ref.get()
            
            if not doc.exists:
                print(f"❌ No rule found with identifier: {identifier}")
                return
            
            doc_ref.delete()
            print(f"✅ Removed routing rule for {identifier}")
            
        except Exception as e:
            print(f"❌ Error removing rule: {e}")
    
    def set_default_rule(self, action: str, target_url: Optional[str] = None, hold_message: Optional[str] = None):
        """Set the default routing rule."""
        try:
            route_action = RouteAction(action.lower())
        except ValueError:
            print(f"❌ Invalid action: {action}")
            print("   Valid actions: forward, hold, block")
            return
        
        if route_action == RouteAction.FORWARD and not target_url:
            print("❌ --target-url is required for 'forward' action")
            return
        
        if self.use_api:
            self._set_default_rule_via_api(action, target_url, hold_message)
        else:
            self._set_default_rule_direct(action, target_url, hold_message)
    
    def _set_default_rule_via_api(self, action: str, target_url: Optional[str], hold_message: Optional[str]):
        """Set default rule via API."""
        try:
            payload = {
                "action": "set_default",
                "rule_action": action,
                "target_url": target_url,
                "hold_message": hold_message
            }
            
            headers = {"Authorization": f"Bearer {self.admin_secret}"}
            response = requests.post(f"{self.api_url}/admin/rules", json=payload, headers=headers)
            
            if response.status_code == 200:
                print(f"✅ Set default routing rule: {action}")
                if target_url:
                    print(f"   Target URL: {target_url}")
                if hold_message:
                    print(f"   Hold message: {hold_message}")
            else:
                print(f"❌ Failed to set default rule: {response.status_code} {response.text}")
                
        except Exception as e:
            print(f"❌ Error setting default rule via API: {e}")
    
    def _set_default_rule_direct(self, action: str, target_url: Optional[str], hold_message: Optional[str]):
        """Set default rule directly in Firestore."""
        rule = RoutingRule(
            action=RouteAction(action.lower()),
            target_url=target_url,
            hold_message=hold_message,
            priority=0
        )
        
        rule_data = rule.__dict__.copy()
        rule_data['action'] = rule.action.value
        
        self.rules_collection.document("default").set(rule_data)
        print(f"✅ Set default routing rule: {action}")
        if target_url:
            print(f"   Target URL: {target_url}")
        if hold_message:
            print(f"   Hold message: {hold_message}")
    
    def _matches_pattern(self, user_id: str, pattern: str) -> bool:
        """Simple pattern matching."""
        if pattern.endswith("*"):
            return user_id.startswith(pattern[:-1])
        return user_id == pattern
    
    def show_stats(self):
        """Show routing statistics."""
        try:
            docs = self.rules_collection.get()
            total_rules = len(docs)
            
            actions = {}
            user_specific = 0
            pattern_based = 0
            
            for doc in docs:
                data = doc.to_dict()
                if data:
                    action = data.get('action', 'unknown')
                    actions[action] = actions.get(action, 0) + 1
                    
                    if data.get('user_id'):
                        user_specific += 1
                    elif data.get('user_pattern'):
                        pattern_based += 1
            
            print(f"\n📊 Routing Statistics:")
            print(f"   Total rules: {total_rules}")
            print(f"   User-specific rules: {user_specific}")
            print(f"   Pattern-based rules: {pattern_based}")
            print(f"   Actions breakdown:")
            for action, count in actions.items():
                print(f"     {action}: {count}")
                
        except Exception as e:
            print(f"❌ Error getting statistics: {e}")

def main():
    parser = argparse.ArgumentParser(description="Manage WhatsApp routing rules")
    parser.add_argument("--project", help="Firestore project ID", 
                       default=os.getenv("FIRESTORE_PROJECT"))
    parser.add_argument("--database", help="Firestore database name", 
                       default=os.getenv("FIRESTORE_DATABASE", "(default)"))
    parser.add_argument("--api-url", help="Router service URL (for API mode)", 
                       default=os.getenv("ROUTER_API_URL"))
    parser.add_argument("--admin-secret", help="Admin secret for API authentication", 
                       default=os.getenv("ADMIN_SECRET"))
    parser.add_argument("--use-api", action="store_true", 
                       help="Use API mode instead of direct Firestore access")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Add rule command
    add_parser = subparsers.add_parser("add", help="Add a new routing rule")
    add_parser.add_argument("action", choices=["forward", "hold", "block"], 
                           help="Routing action")
    add_parser.add_argument("--user-id", help="Specific user ID to route")
    add_parser.add_argument("--user-pattern", help="User ID pattern to match (e.g., '123*')")
    add_parser.add_argument("--target-url", help="Target URL for forwarding")
    add_parser.add_argument("--hold-message", help="Message to send for hold action")
    add_parser.add_argument("--priority", type=int, default=0, 
                           help="Rule priority (higher = checked first)")
    
    # List rules command
    list_parser = subparsers.add_parser("list", help="List routing rules")
    list_parser.add_argument("--user-id", help="Show rules for specific user")
    
    # Remove rule command
    remove_parser = subparsers.add_parser("remove", help="Remove a routing rule")
    remove_parser.add_argument("identifier", help="User ID or pattern to remove")
    
    # Set default command
    default_parser = subparsers.add_parser("default", help="Set default routing rule")
    default_parser.add_argument("action", choices=["forward", "hold", "block"])
    default_parser.add_argument("--target-url", help="Target URL for forwarding")
    default_parser.add_argument("--hold-message", help="Message to send for hold action")
    
    # Stats command
    subparsers.add_parser("stats", help="Show routing statistics")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        admin = RouterAdmin(
            project=args.project, 
            database=args.database,
            use_api=args.use_api,
            api_url=args.api_url,
            admin_secret=args.admin_secret
        )
        
        if args.command == "add":
            admin.add_rule(
                action=args.action,
                user_id=args.user_id,
                user_pattern=args.user_pattern,
                target_url=args.target_url,
                hold_message=args.hold_message,
                priority=args.priority
            )
        
        elif args.command == "list":
            admin.list_rules(user_id=args.user_id)
        
        elif args.command == "remove":
            admin.remove_rule(args.identifier)
        
        elif args.command == "default":
            admin.set_default_rule(
                action=args.action,
                target_url=args.target_url,
                hold_message=args.hold_message
            )
        
        elif args.command == "stats":
            admin.show_stats()
            
    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Admin tool error: {e}", exc_info=True)

if __name__ == "__main__":
    main()

# Example usage:
"""
# Direct Firestore access (requires Firestore credentials)
python router_admin.py default forward --target-url https://main-bot.run.app/webhook/whatsapp

# API mode (requires ADMIN_SECRET)
export ADMIN_SECRET="your-strong-secret-here"
export ROUTER_API_URL="https://your-router.run.app"

python router_admin.py --use-api default forward --target-url https://main-bot.run.app/webhook/whatsapp

# API mode with explicit parameters
python router_admin.py --use-api --api-url https://your-router.run.app --admin-secret your-secret \
  add forward --user-id 1234567890 --target-url https://test-bot.run.app/webhook/whatsapp

# List rules for user (API mode)
python router_admin.py --use-api list --user-id 1234567890

# Set environment variables for easier API usage
export ADMIN_SECRET="your-strong-secret-here"
export ROUTER_API_URL="https://your-router.run.app"

# Then you can use shorter commands
python router_admin.py --use-api add hold --user-id 9876543210 --hold-message "Maintenance mode"
python router_admin.py --use-api remove 1234567890
python router_admin.py --use-api default forward --target-url https://main-bot.run.app/webhook/whatsapp
"""