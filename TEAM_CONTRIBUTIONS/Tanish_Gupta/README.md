# Tanish Gupta - Contribution Summary

## Role: Core Voting Logic & Data Management Developer

### Part 3: Voting System Implementation

Implemented the main voting functionality with duplicate vote prevention, results display, and data integrity features.

---

## Files Contributed

### 1. **index.ejs** - Main Voting Page (115 lines)
- Designed the voting interface with poll question and options
- Implemented "already voted" status display with visual indicators
- Shows which option the user previously selected
- Disables voting form after user has voted
- Green badge showing "Your Vote" on selected option

### 2. **results.ejs** - Results Display Page (41 lines)
- Created results visualization with vote counts
- Shows percentages for each option
- Bar graph visualization with color-coded progress bars
- Real-time vote tallies
- Clean and professional results layout

### 3. **index.js (Voting Routes)** - Core Voting Logic (~150 lines)
- Implemented POST /vote route (vote submission with validation)
- Implemented GET /results route (results page display)
- Added duplicate vote prevention system
- Vote tracking by user ID in votes.json
- Vote verification and validation
- Error handling for invalid votes

---

## Security Features Implemented

### 🗳️ Vote Duplication Prevention
- Track votes by user ID (not IP address)
- Store voted user IDs in votes.json
- Check before accepting each vote
- Reject duplicate votes with error message
- Persist vote tracking across sessions
- Show voted status on UI

### ✅ Input Validation
- Validate poll ID exists
- Validate option is within range
- Check poll exists before recording vote
- Verify option is valid for the poll
- Sanitize all voting inputs

### 🔒 Authentication Protection
- All voting routes protected with requireAuth
- Only logged-in users can vote
- Session-based user identification
- Automatic redirect to login if not authenticated

### 📊 Vote Integrity
- Atomic vote recording (polls.json and votes.json)
- Consistent data structure
- Error recovery mechanisms
- Transaction-like behavior for data updates

---

## Technical Implementation

### Duplicate Vote Prevention Algorithm
```
1. Check if votes[pollId] contains userId
2. If yes → reject with "already voted" error
3. If no → record vote in both files
4. Update poll vote counts
5. Save to disk atomically
```

### Vote Tracking Structure
```json
{
  "1": ["user123", "user456"],  // Poll ID 1 → Array of voter IDs
  "2": ["user789"]               // Poll ID 2 → Array of voter IDs
}
```

### User Experience Features
- "✓ You voted for: Python" confirmation message
- Highlights user's choice with colored background
- Displays "Your Vote" badge on selected option
- Disables all form controls after voting
- "View Results" link appears after voting

---

## Code Statistics

**Lines of Code Contributed: ~306 lines**

| File | Lines | Purpose |
|------|-------|---------|
| index.ejs | 115 | Voting interface |
| results.ejs | 41 | Results display |
| index.js (voting) | 150 | Vote logic & routes |

---

## Skills Demonstrated

- Express.js route handling and middleware
- Complex data validation and sanitization
- User session management and tracking
- File I/O operations with JSON
- Error handling and user feedback
- Array manipulation for vote tracking
- Conditional rendering in EJS templates
- Vote counting and percentage algorithms

---

## Testing Completed

✅ Vote duplication prevention (1 vote per user per poll)  
✅ Option validation (within valid range)  
✅ Poll existence verification  
✅ Vote count incrementation  
✅ Data persistence across sessions  
✅ Accurate percentage calculations  
✅ Real-time results updates  

---

**Contribution Date:** November 2025  
**Project:** SecurePolls - Secure Voting Application  
**Status:** ✅ Complete and Production Ready
