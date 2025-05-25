# router_admin.py
"""
Administration tool for managing WhatsApp routing rules.
Standalone version for the router service.
"""

import argparse
import logging
import os
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
    
    def __init__(self, project: Optional[str] = None, database: Optional[str] = None):
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
        
        rule = RoutingRule(
            user_id=user_id,
            user_pattern=user_pattern,
            action=route_action,
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
        try:
            if user_id:
                print(f"\n📋 Routing rules for user {user_id}:")
                # Get user-specific rules
                user_docs = self.rules_collection.where("user_id", "==", user_id).get()
                rules = []
                for doc in user_docs:
                    data = doc.to_dict()
                    if data and 'action' in data:
                        data['action'] = RouteAction(data['action'])
                        rules.append(RoutingRule(**data))
                
                # Get pattern-based rules that might match
                pattern_docs = self.rules_collection.where("user_pattern", "!=", None).get()
                for doc in pattern_docs:
                    data = doc.to_dict()
                    if data and 'action' in data:
                        data['action'] = RouteAction(data['action'])
                        rule = RoutingRule(**data)
                        if rule.user_pattern and self._matches_pattern(user_id, rule.user_pattern):
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
        
        rule = RoutingRule(
            action=route_action,
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
        admin = RouterAdmin(project=args.project, database=args.database)
        
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
# Set default rule to forward to main bot
python router_admin.py default forward --target-url https://my-main-bot.run.app/webhook/whatsapp

# Route specific user to test bot
python router_admin.py add forward --user-id 1234567890 --target-url https://test-bot.run.app/webhook/whatsapp

# Route all test users to test environment
python router_admin.py add forward --user-pattern "test*" --target-url https://test-bot.run.app/webhook/whatsapp --priority 10

# Put a user on hold
python router_admin.py add hold --user-id 9876543210 --hold-message "Account under review. Contact support."

# Block a user
python router_admin.py add block --user-id 5555555555

# List all rules
python router_admin.py list

# List rules that would apply to specific user
python router_admin.py list --user-id 1234567890

# Remove a rule
python router_admin.py remove 1234567890

# Show statistics
python router_admin.py stats

# Use with specific Firestore project
python router_admin.py --project my-project-id --database my-db list
"""