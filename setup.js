const fs = require('fs');
const bcrypt = require('bcrypt');
const path = require('path');

const ADMIN_PASSWORD = 'AdminPassword123';

async function setup() {
    try {
        console.log('🚀 Setting up Secure Voting Application...\n');

        const dataDir = path.join(__dirname, 'data');
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir);
            console.log('✅ Created data directory');
        }

        const logsDir = path.join(__dirname, 'logs');
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir);
            console.log('✅ Created logs directory');
        }

        console.log('🔐 Hashing admin password...');
        const adminPasswordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
        const credentials = {
            username: 'admin',
            password: adminPasswordHash
        };
        fs.writeFileSync(
            path.join(dataDir, 'credentials.json'),
            JSON.stringify(credentials, null, 2)
        );
        console.log('✅ Created credentials.json');

        const polls = [
            {
                id: 1,
                question: 'What is your favorite programming language?',
                options: ['JavaScript', 'Python', 'Java', 'C++']
            }
        ];
        fs.writeFileSync(
            path.join(dataDir, 'polls.json'),
            JSON.stringify(polls, null, 2)
        );
        console.log('✅ Created polls.json');

        fs.writeFileSync(
            path.join(dataDir, 'users.json'),
            JSON.stringify([], null, 2)
        );
        console.log('✅ Created users.json');

        fs.writeFileSync(
            path.join(dataDir, 'votes.json'),
            JSON.stringify({}, null, 2)
        );
        console.log('✅ Created votes.json');

        console.log('\n✨ Setup completed successfully!');
        console.log('\n📝 Admin Credentials:');
        console.log('   Username: admin');
        console.log('   Password: ' + ADMIN_PASSWORD);
        console.log('\n⚠️  Please change the admin password before deploying to production!');
        console.log('\n🚀 Start the application with: npm start');

    } catch (error) {
        console.error('❌ Setup failed:', error.message);
        process.exit(1);
    }
}

setup();
