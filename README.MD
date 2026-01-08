$csvUrl = 'https://docs.google.com/spreadsheets/.../export?format=csv&gid=0';

Usage Example

```bash
curl -X POST http://yourdomain.com/filter_call \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "PhoneNumber": "0123465789",
    "IsSpam": true,
    "Confidence": 9,
    "CallType": "scam"
  }'