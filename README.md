# WhatsApp Router Service

A standalone service that routes WhatsApp messages to different bot endpoints based on configurable rules stored in Firestore.

## 🎯 Overview

This router service sits between WhatsApp and your bots, intelligently routing messages based on:
- **User-specific rules**: Route specific phone numbers to designated endpoints
- **Pattern-based rules**: Route users matching patterns (e.g., `test*`) to specific endpoints  
- **Priority system**: Higher priority rules are checked first
- **Default fallback**: Configurable default action for unmatched users

### Supported Actions
- **`forward`**: Route messages to another bot endpoint
- **`hold`**: Send holding message to users (useful during maintenance)
- **`block`**: Silently ignore messages from specific users

## 🚀 Quick Start

### Prerequisites
- Google Cloud Project with Firestore enabled
- WhatsApp Business API credentials
- Docker (for Cloud Run deployment)

### Local Development

1. **Clone and setup**:
```bash
git clone <your-repo>
cd whatsapp-router
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install google-cloud-firestore flask functions-framework requests
```

2. **Set environment variables**:
```bash
export PHONE_NUMBER_ID="your_phone_number_id"
export WABA_ACCESS_TOKEN="your_access_token"
export WHATSAPP_VERIFY_TOKEN="your_verify_token"
export FIRESTORE_PROJECT="your-project-id"  # optional
export FIRESTORE_DATABASE="(default)"       # optional
```

3. **Run locally**:
```bash
python main.py
```

The service will start on `http://localhost:8080`

## 🔧 Google Cloud Run Deployment

### Method 1: Deploy with gcloud CLI

1. **Install Google Cloud CLI** and authenticate:
```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

2. **Enable required APIs**:
```bash
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable firestore.googleapis.com
```

3. **Create Dockerfile**:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install google-cloud-firestore flask functions-framework requests

# Copy application files
COPY main.py .
COPY router_admin.py .

# Expose port
EXPOSE 8080

# Run the application
CMD ["python", "main.py"]
```

4. **Deploy to Cloud Run**:
```bash
gcloud run deploy whatsapp-router \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars PHONE_NUMBER_ID="your_phone_number_id" \
  --set-env-vars WABA_ACCESS_TOKEN="your_access_token" \
  --set-env-vars WHATSAPP_VERIFY_TOKEN="your_verify_token" \
  --set-env-vars FIRESTORE_PROJECT="your-project-id"
```

### Method 2: Deploy via Google Cloud Console

1. Go to [Cloud Run Console](https://console.cloud.google.com/run)
2. Click "Create Service"
3. Choose "Deploy one revision from a source repository"
4. Connect your GitHub repository
5. Set build configuration:
   - **Source**: `/` (root directory)
   - **Build type**: Dockerfile
6. Configure service:
   - **Region**: Choose your preferred region
   - **Authentication**: Allow unauthenticated invocations
7. Set environment variables in "Variables & Secrets":
   ```
   PHONE_NUMBER_ID=your_phone_number_id
   WABA_ACCESS_TOKEN=your_access_token
   WHATSAPP_VERIFY_TOKEN=your_verify_token
   FIRESTORE_PROJECT=your-project-id
   ```
8. Deploy

### Method 3: Deploy as Cloud Function

1. **Prepare function**:
```bash
# Create requirements.txt
echo "google-cloud-firestore
flask
functions-framework
requests" > requirements.txt
```

2. **Deploy**:
```bash
gcloud functions deploy whatsapp-router \
  --runtime python311 \
  --trigger-http \
  --allow-unauthenticated \
  --entry-point main_handler \
  --set-env-vars PHONE_NUMBER_ID="your_phone_number_id" \
  --set-env-vars WABA_ACCESS_TOKEN="your_access_token" \
  --set-env-vars WHATSAPP_VERIFY_TOKEN="your_verify_token" \
  --set-env-vars FIRESTORE_PROJECT="your-project-id"
```

## 🔧 WhatsApp Webhook Configuration

After deployment, configure your WhatsApp webhook:

1. **Get your service URL**:
   - Cloud Run: `https://whatsapp-router-xxx-uc.a.run.app`
   - Cloud Functions: `https://us-central1-project-id.cloudfunctions.net/whatsapp-router`

2. **Set webhook URL** in WhatsApp Business API:
   ```
   https://your-service-url/webhook/whatsapp
   ```

3. **Test webhook verification**:
   ```bash
   curl "https://your-service-url/webhook/whatsapp?hub.verify_token=your_verify_token&hub.challenge=test123"
   ```

## 🛠️ Managing Routing Rules

Use the `router_admin.py` tool to manage routing rules:

### Setup Admin Tool

```bash
# Install dependencies
pip install google-cloud-firestore

# Set credentials (if not using Cloud Shell)
export GOOGLE_APPLICATION_CREDENTIALS="path/to/service-account.json"
```

### Basic Commands

#### Set Default Rule
Route all unmatched users to your main bot:
```bash
python router_admin.py default forward --target-url https://main-bot.run.app/webhook/whatsapp
```

#### Add User-Specific Rules
Route specific users to different endpoints:
```bash
# Route user to test bot
python router_admin.py add forward \
  --user-id 1234567890 \
  --target-url https://test-bot.run.app/webhook/whatsapp

# Put user on hold during maintenance
python router_admin.py add hold \
  --user-id 9876543210 \
  --hold-message "Service temporarily unavailable. Back online soon!"

# Block unwanted user
python router_admin.py add block --user-id 5555555555
```

#### Pattern-Based Rules
Route users matching patterns:
```bash
# Route all test users to test environment
python router_admin.py add forward \
  --user-pattern "test*" \
  --target-url https://test-bot.run.app/webhook/whatsapp \
  --priority 10

# Route all users from specific country code
python router_admin.py add forward \
  --user-pattern "44*" \
  --target-url https://uk-bot.run.app/webhook/whatsapp \
  --priority 5
```

#### List and Manage Rules
```bash
# List all rules
python router_admin.py list

# List rules for specific user
python router_admin.py list --user-id 1234567890

# Remove a rule
python router_admin.py remove 1234567890

# Show statistics
python router_admin.py stats
```

### Advanced Admin Usage

#### Using Different Firestore Projects
```bash
python router_admin.py --project my-other-project --database my-db list
```

#### Priority System
Rules are checked in priority order (highest first):
```bash
# High priority rule for VIP users
python router_admin.py add forward \
  --user-pattern "vip*" \
  --target-url https://vip-bot.run.app/webhook/whatsapp \
  --priority 100

# Medium priority for test users  
python router_admin.py add forward \
  --user-pattern "test*" \
  --target-url https://test-bot.run.app/webhook/whatsapp \
  --priority 50

# Low priority default
python router_admin.py default forward \
  --target-url https://main-bot.run.app/webhook/whatsapp
```

## 📊 Monitoring and Debugging

### Health Check
```bash
curl https://your-service-url/
```

### Check Rules for User
```bash
curl "https://your-service-url/admin/rules?user_id=1234567890"
```

### View Logs
```bash
# Cloud Run logs
gcloud run logs tail whatsapp-router --region us-central1

# Cloud Functions logs  
gcloud functions logs read whatsapp-router
```

## 🔒 Security Best Practices

1. **Environment Variables**: Never commit credentials to code
2. **IAM Roles**: Use minimal required permissions
3. **Firestore Rules**: Secure your Firestore database
4. **HTTPS Only**: Ensure all endpoints use HTTPS
5. **Verify Token**: Use a strong, unique verification token

### Recommended Firestore Security Rules
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /whatsapp_routing_rules/{document} {
      allow read, write: if request.auth != null;
    }
  }
}
```

## 🚨 Troubleshooting

### Common Issues

1. **"Router not initialized"**:
   - Check environment variables are set correctly
   - Verify Firestore permissions

2. **"Invalid verification token"**:
   - Ensure `WHATSAPP_VERIFY_TOKEN` matches WhatsApp configuration

3. **"Failed to forward message"**:
   - Check target URL is accessible
   - Verify target bot is running and responding

4. **Messages not being routed**:
   - Check rules with `python router_admin.py list --user-id <number>`
   - Verify default rule is set
   - Check logs for errors

### Debug Mode
Run locally with debug logging:
```bash
export FLASK_DEBUG=1
python main.py
```

## 📝 Example Deployment Workflow

1. **Deploy main bot** to Cloud Run
2. **Deploy router service** to Cloud Run  
3. **Set default rule** to forward to main bot:
   ```bash
   python router_admin.py default forward --target-url https://main-bot-xxx.run.app/webhook/whatsapp
   ```
4. **Update WhatsApp webhook** to point to router
5. **Test** with a message - should route to main bot
6. **Gradually migrate users** to new bot instances as needed

## 🤝 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Cloud Run/Functions logs
3. Test routing rules with the admin tool
4. Verify WhatsApp webhook configuration

## 📄 License

This project is licensed under the MIT License.