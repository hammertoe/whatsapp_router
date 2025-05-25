source .env
gcloud functions deploy whatsapp_webhook \
  --gen2 \
  --runtime=python311 \
  --region=us-central1 \
  --entry-point=cloud_function_handler \
  --trigger-http \
  --allow-unauthenticated \
  --memory=512MB \
  --set-env-vars=WHATSAPP_VERIFY_TOKEN=${WHATSAPP_VERIFY_TOKEN} \
  --set-env-vars=WABA_ACCESS_TOKEN=${WABA_ACCESS_TOKEN} \
  --set-env-vars=PHONE_NUMBER_ID=${PHONE_NUMBER_ID} \
  --set-env-vars=ADMIN_SECRET=${ADMIN_SECRET}
