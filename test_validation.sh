#!/bin/bash

echo "🧪 Testing Input Validation..."
echo ""

# Test if server is running
if ! lsof -i:3000 > /dev/null 2>&1; then
    echo "❌ Server is not running on port 3000"
    exit 1
fi

echo "✅ Server is running"
echo ""

# Check if validation code exists
if grep -q "body('username')" index.js && grep -q "isLength({ min: 3 })" index.js; then
    echo "✅ Username validation found (min 3 chars)"
else
    echo "❌ Username validation missing"
fi

if grep -q "body('password')" index.js && grep -q "isLength({ min: 8 })" index.js; then
    echo "✅ Password validation found (min 8 chars)"
else
    echo "❌ Password validation missing"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📝 MANUAL TEST REQUIRED:"
echo ""
echo "1. Open: http://localhost:3000/register"
echo "2. Try registering with:"
echo "   Username: a"
echo "   Password: b"
echo ""
echo "3. You MUST see error:"
echo "   'Username must be 3+ chars, password must be 8+ chars'"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
