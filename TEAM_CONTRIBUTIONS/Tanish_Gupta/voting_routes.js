// Tanish Gupta - Voting Logic & Data Management
// Part 3: Voting System with Duplicate Prevention, Results Display

const express = require('express');
const fs = require('fs');
const path = require('path');

// Vote Route - Handles vote submission with duplicate prevention
app.post('/vote', isAuthenticated, csrfProtection, (req, res) => {
    try {
        const pollId = parseInt(req.body.pollId);
        const optionValue = req.body.option;
        
        console.log('Vote data received:', { pollId, optionValue, body: req.body });

        const users = readJSON(USERS_FILE);
        const votes = readJSON(VOTES_FILE);
        const polls = readJSON(POLLS_FILE);
        const poll = polls.find(p => p.id === pollId);

        // Validate poll exists
        if (!poll) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Invalid Poll',
                errorMessage: 'The poll you are trying to vote on does not exist.'
            });
        }

        // Find option index - handle both number index and option name
        let optionIndex;
        if (!isNaN(parseInt(optionValue))) {
            optionIndex = parseInt(optionValue);
        } else {
            optionIndex = poll.options.indexOf(optionValue);
        }

        // Validate option is within valid range
        if (optionIndex < 0 || optionIndex >= poll.options.length) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Invalid Option',
                errorMessage: 'The option you selected is not valid.'
            });
        }

        const currentUser = users.find(u => u.id === req.session.userId);
        
        // Check if user already voted (user record check)
        if (currentUser && currentUser.lastVote === pollId) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Already Voted',
                errorMessage: 'You have already voted in this poll. Vote duplication is not allowed.'
            });
        }

        // Initialize poll votes array if it doesn't exist
        if (!votes[pollId.toString()]) {
            votes[pollId.toString()] = [];
        }

        // Check for duplicate vote (votes.json check)
        const alreadyVoted = votes[pollId.toString()].find(v => v.userId === req.session.userId);
        if (alreadyVoted) {
            return res.status(400).render('error', {
                session: req.session,
                csrfToken: req.csrfToken(),
                errorTitle: 'Already Voted',
                errorMessage: 'You have already voted in this poll. Vote duplication is not allowed.'
            });
        }

        // Record vote with userId, option, and timestamp
        votes[pollId.toString()].push({
            userId: req.session.userId,
            option: optionIndex,
            timestamp: new Date().toISOString()
        });
        writeJSON(VOTES_FILE, votes);
        
        console.log('Vote recorded:', votes[pollId.toString()]);

        // Update user's lastVote with pollId
        if (currentUser) {
            currentUser.lastVote = pollId;
            currentUser.lastVoteOption = optionIndex;
            writeJSON(USERS_FILE, users);
        }

        // Log vote
        logSecurityEvent(`Vote cast by user: ${req.session.username} for poll: ${pollId}, option: ${poll.options[optionIndex]}`);

        res.redirect('/vote');
    } catch (error) {
        console.error('Voting error:', error);
        res.status(500).render('error', {
            session: req.session,
            csrfToken: req.csrfToken(),
            errorTitle: 'Voting Error',
            errorMessage: 'An error occurred while processing your vote.'
        });
    }
});

// Voting Page Route - Display poll and voting status
app.get('/vote', isAuthenticated, csrfProtection, (req, res) => {
    const polls = readJSON(POLLS_FILE);
    const votes = readJSON(VOTES_FILE);
    const users = readJSON(USERS_FILE);
    const currentUser = users.find(u => u.id === req.session.userId);

    if (polls.length === 0) {
        return res.render('index', {
            session: req.session,
            csrfToken: req.csrfToken(),
            poll: null,
            hasVoted: false,
            userVote: null,
            isAdmin: false
        });
    }

    const poll = polls[0]; // Single standard poll
    const pollVotes = votes[poll.id.toString()] || [];
    const userVoteRecord = pollVotes.find(v => v.userId === req.session.userId);
    const hasVoted = !!userVoteRecord || (currentUser && currentUser.lastVote === poll.id);
    const userVote = userVoteRecord ? poll.options[userVoteRecord.option] : 
                     (currentUser && currentUser.lastVoteOption !== undefined) ? poll.options[currentUser.lastVoteOption] : null;

    res.render('index', { 
        session: req.session,
        csrfToken: req.csrfToken(),
        poll: poll,
        hasVoted: hasVoted,
        userVote: userVote,
        isAdmin: false
    });
});

// Results Route - Display voting results with calculations
app.get('/results', isAuthenticated, csrfProtection, (req, res) => {
    const polls = readJSON(POLLS_FILE);
    const votes = readJSON(VOTES_FILE);

    if (polls.length === 0) {
        return res.render('results', {
            session: req.session,
            csrfToken: req.csrfToken(),
            poll: null,
            results: {}
        });
    }

    const poll = polls[0]; // Single standard poll
    const pollVotes = votes[poll.id.toString()] || [];
    
    // Count votes per option from the votes array
    const results = {};
    poll.options.forEach((_, index) => {
        results[index] = 0;
    });
    
    pollVotes.forEach(vote => {
        if (vote.option !== undefined && vote.option !== null) {
            results[vote.option] = (results[vote.option] || 0) + 1;
        }
    });

    res.render('results', { 
        session: req.session,
        csrfToken: req.csrfToken(),
        poll: poll,
        results: results
    });
});

// Data Management Functions
function readJSON(filepath) {
    try {
        if (!fs.existsSync(filepath)) {
            return filepath === POLLS_FILE ? [] : 
                   filepath === VOTES_FILE ? {} : [];
        }
        const data = fs.readFileSync(filepath, 'utf8');
        return data ? JSON.parse(data) : [];
    } catch (error) {
        console.error(`Error reading ${filepath}:`, error);
        return [];
    }
}

function writeJSON(filepath, data) {
    try {
        fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error(`Error writing ${filepath}:`, error);
    }
}

module.exports = {
    readJSON,
    writeJSON
};
