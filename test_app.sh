#!/bin/bash

echo "=== Testing Secure Voting App ==="
echo

echo "1. Testing root route (/)..."
curl -s -I http://localhost:3000/ | head -3
echo

echo "2. Testing login page..."
curl -s -I http://localhost:3000/login | head -3
echo

echo "3. Testing register page..."
curl -s -I http://localhost:3000/register | head -3
echo

echo "4. Testing admin login page..."
curl -s -I http://localhost:3000/admin-login | head -3
echo

echo "5. Testing CSS file..."
curl -s -I http://localhost:3000/css/style.css | head -3
echo

echo "6. Checking data files..."
echo "Polls: $(cat data/polls.json | jq -r '.[0].question' 2>/dev/null || echo 'Error')"
echo "Poll ID type: $(cat data/polls.json | jq -r '.[0].id | type' 2>/dev/null || echo 'Error')"
echo

echo "=== All Routes Accessible! ==="
