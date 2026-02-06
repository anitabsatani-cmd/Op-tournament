/**
 * SENIOR BACKEND ENGINEER - ESPORTS TOURNAMENT SERVER
 * Single File: index.js
 * Tech Stack: Node.js, Express, Firebase Admin, Cashfree
 */

const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { Cashfree } = require('cashfree-pg'); // Assuming v3 SDK
const crypto = require('crypto');
const bodyParser = require('body-parser');

// --- CONFIGURATION ---
// In production, use process.env for these values
const PORT = process.env.PORT || 3000;
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID || "YOUR_APP_ID";
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY || "YOUR_SECRET_KEY";
const CASHFREE_ENV = process.env.CASHFREE_ENV || "SANDBOX"; // or PRODUCTION
const FIREBASE_SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT 
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT) 
  : require('./serviceAccountKey.json'); // Local fallback

// --- INITIALIZATION ---
const app = express();
app.use(cors({ origin: true }));

// Webhook needs RAW body for signature verification
app.use('/webhook/cashfree', bodyParser.raw({ type: 'application/json' }));
app.use(express.json());

admin.initializeApp({
    credential: admin.credential.cert(FIREBASE_SERVICE_ACCOUNT)
});
const db = admin.firestore();

Cashfree.XClientId = CASHFREE_APP_ID;
Cashfree.XClientSecret = CASHFREE_SECRET_KEY;
Cashfree.XEnvironment = Cashfree.Environment[CASHFREE_ENV];

// --- MIDDLEWARE ---

/**
 * Verify Firebase ID Token
 * Populates req.user with { uid, email, ... }
 */
const verifyAuth = async (req, res, next) => {
    try {
        const header = req.headers.authorization;
        if (!header || !header.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized: No token provided' });
        }
        const token = header.split('Bearer ')[1];
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = decodedToken;
        next();
    } catch (error) {
        console.error("Auth Error:", error.message);
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

/**
 * Admin Guard (Simple check for specific email or custom claim)
 * In production, use Custom Claims (isAdmin: true)
 */
const verifyAdmin = async (req, res, next) => {
    // Replace with your robust admin check logic
    const ADMIN_EMAILS = ["admin@esports.com", "fenilsatani8487@gmail.com"]; 
    if (!req.user || !ADMIN_EMAILS.includes(req.user.email)) {
        return res.status(403).json({ error: 'Forbidden: Admin access only' });
    }
    next();
};

// --- HELPER FUNCTIONS ---

const generateReferralCode = () => {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
};

// --- ROUTES ---

/**
 * 1. AUTH: SIGNUP
 * Idempotent creation of user document
 */
app.post('/auth/signup', verifyAuth, async (req, res) => {
    try {
        const { username, email, referralCode } = req.body;
        const uid = req.user.uid;
        
        const userRef = db.collection('users').doc(uid);
        const userDoc = await userRef.get();

        if (userDoc.exists) {
            return res.status(200).json({ message: 'User already exists', user: userDoc.data() });
        }

        const newUser = {
            username: username || 'Player',
            email: email || req.user.email,
            wallet: 0,
            totalXP: 0,
            joinedMatches: [],
            referralCode: generateReferralCode(),
            referredBy: referralCode || null,
            matchesPlayed: 0,
            totalKills: 0,
            dailyStreak: 0,
            lastDailyClaim: 0,
            isVIP: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await userRef.set(newUser);
        return res.status(201).json({ message: 'User created', user: newUser });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

/**
 * 2. PAYMENT: CREATE ORDER
 * Initiates Cashfree Order, Stores PENDING Transaction
 */
app.post('/wallet/createOrder', verifyAuth, async (req, res) => {
    try {
        const { amount } = req.body;
        const uid = req.user.uid;

        if (!amount || amount < 1) return res.status(400).json({ error: 'Invalid amount' });

        const orderId = `ORDER_${uid}_${Date.now()}`;
        const userRef = db.collection('users').doc(uid);
        const userDoc = await userRef.get();
        if(!userDoc.exists) return res.status(404).json({error: 'User not found'});
        const userData = userDoc.data();

        // 1. Create Order in Cashfree
        const request = {
            order_amount: amount,
            order_currency: "INR",
            order_id: orderId,
            customer_details: {
                customer_id: uid,
                customer_phone: "9999999999", // Required by CF, can be dummy if not collecting
                customer_name: userData.username || "Gamer",
                customer_email: userData.email || "user@example.com"
            },
            order_meta: {
                return_url: `https://your-frontend-url.com/wallet?order_id=${orderId}`
            }
        };

        const response = await Cashfree.PGCreateOrder("2022-09-01", request);
        const paymentSessionId = response.data.payment_session_id;

        // 2. Create Transaction Record (PENDING)
        await db.collection('transactions').doc(orderId).set({
            userId: uid,
            type: 'deposit',
            amount: parseFloat(amount),
            status: 'PENDING',
            orderId: orderId,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ payment_session_id: paymentSessionId, order_id: orderId });

    } catch (error) {
        console.error("Payment Init Error:", error);
        res.status(500).json({ error: 'Payment initialization failed' });
    }
});

/**
 * 3. PAYMENT: WEBHOOK (CRITICAL)
 * Handles Wallet Updates securely
 */
app.post('/webhook/cashfree', async (req, res) => {
    try {
        // 1. Verify Signature
        const ts = req.headers["x-webhook-timestamp"];
        const signature = req.headers["x-webhook-signature"];
        const rawBody = req.body.toString(); // Need raw body for HMAC

        if (!ts || !signature) return res.status(400).send("Missing Headers");

        const genSignature = crypto
            .createHmac('sha256', CASHFREE_SECRET_KEY)
            .update(ts + rawBody)
            .digest('base64');

        if (signature !== genSignature) {
            console.error("Webhook Signature Mismatch");
            return res.status(403).send("Invalid Signature");
        }

        // 2. Process Data
        const data = JSON.parse(rawBody);
        const type = data.type; // PAYMENT_SUCCESS_WEBHOOK, etc.

        if (type === "PAYMENT_SUCCESS_WEBHOOK") {
            const orderId = data.data.order.order_id;
            const txnRef = db.collection('transactions').doc(orderId);

            await db.runTransaction(async (t) => {
                const txnDoc = await t.get(txnRef);
                if (!txnDoc.exists) return; // Ignore unknown orders
                if (txnDoc.data().status === 'SUCCESS') return; // Idempotency check

                const userId = txnDoc.data().userId;
                const amount = txnDoc.data().amount;
                const userRef = db.collection('users').doc(userId);

                // Update Wallet
                t.update(userRef, {
                    wallet: admin.firestore.FieldValue.increment(amount)
                });

                // Update Transaction
                t.update(txnRef, {
                    status: 'SUCCESS',
                    gatewayRef: data.data.payment.cf_payment_id,
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                });
            });
        } 
        else if (type === "PAYMENT_FAILED_WEBHOOK") {
             const orderId = data.data.order.order_id;
             await db.collection('transactions').doc(orderId).update({ status: 'FAILED' });
        }

        res.status(200).send("OK");
    } catch (error) {
        console.error("Webhook Error:", error);
        res.status(500).send("Server Error");
    }
});

/**
 * 4. MATCH: JOIN
 * Transactional join logic with balance deduction
 */
app.post('/match/join', verifyAuth, async (req, res) => {
    const { matchId, gameUids } = req.body; // gameUids is array of in-game strings
    const userId = req.user.uid;

    if (!matchId || !Array.isArray(gameUids) || gameUids.length === 0) {
        return res.status(400).json({ error: 'Invalid join data' });
    }

    try {
        await db.runTransaction(async (t) => {
            // Refs
            const matchRef = db.collection('matches').doc(matchId);
            const userRef = db.collection('users').doc(userId);
            const teamRef = matchRef.collection('teams').doc(userId);

            // Reads
            const matchDoc = await t.get(matchRef);
            const userDoc = await t.get(userRef);
            const teamDoc = await t.get(teamRef);

            // Validations
            if (!matchDoc.exists) throw new Error("Match not found");
            const matchData = matchDoc.data();

            if (matchData.status !== 'Upcoming') throw new Error("Match is not open for joining");
            if (matchData.joinedCount >= matchData.maxPlayers) throw new Error("Match Full");
            if (teamDoc.exists) throw new Error("You have already joined this match");

            // Slot Availability
            // In a Squad mode, slots might mean Teams, here we assume joinedCount = number of Teams/Slots
            const slotsNeeded = 1; // 1 Team = 1 Slot in Tournament
            if ((matchData.joinedCount + slotsNeeded) > matchData.maxPlayers) throw new Error("Not enough slots");

            // Wallet Check
            if (userDoc.data().wallet < matchData.entryFee) throw new Error("Insufficient Balance");

            // Writes
            // 1. Deduct Balance
            t.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(-matchData.entryFee),
                joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
            });

            // 2. Create Team
            t.set(teamRef, {
                ownerUid: userId,
                ownerUsername: userDoc.data().username,
                gameUids: gameUids,
                joinedAt: admin.firestore.FieldValue.serverTimestamp(),
                hasReceivedRewards: false
            });

            // 3. Update Match
            t.update(matchRef, {
                joinedCount: admin.firestore.FieldValue.increment(1)
            });

            // 4. Create Ledger Entry
            const txnRef = db.collection('transactions').doc();
            t.set(txnRef, {
                userId: userId,
                type: 'match_entry',
                matchId: matchId,
                amount: -matchData.entryFee,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: 'Joined successfully' });

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/**
 * 5. REWARDS: DAILY
 * Once per 24h logic
 */
app.post('/rewards/daily', verifyAuth, async (req, res) => {
    const userId = req.user.uid;
    const REWARD_AMOUNT = 10; // Configurable

    try {
        await db.runTransaction(async (t) => {
            const userRef = db.collection('users').doc(userId);
            const userDoc = await t.get(userRef);
            const userData = userDoc.data();

            const now = Date.now();
            const lastClaim = userData.lastDailyClaim ? userData.lastDailyClaim.toMillis() : 0;
            const diffHours = (now - lastClaim) / (1000 * 60 * 60);

            if (diffHours < 24) throw new Error(`Come back in ${Math.ceil(24 - diffHours)} hours`);

            // Logic for streak (simple version)
            const isConsecutive = diffHours < 48; 
            const newStreak = isConsecutive ? (userData.dailyStreak || 0) + 1 : 1;

            t.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(REWARD_AMOUNT),
                lastDailyClaim: admin.firestore.Timestamp.fromMillis(now),
                dailyStreak: newStreak
            });

            const txnRef = db.collection('transactions').doc();
            t.set(txnRef, {
                userId: userId,
                type: 'daily_reward',
                amount: REWARD_AMOUNT,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, amount: REWARD_AMOUNT });

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/**
 * 6. WALLET: WITHDRAW
 * Deduct balance immediately, create Pending Request
 */
app.post('/wallet/withdraw', verifyAuth, async (req, res) => {
    const { amount, upiId } = req.body;
    const userId = req.user.uid;

    if (!amount || amount < 50) return res.status(400).json({ error: "Min withdrawal is 50" });

    try {
        await db.runTransaction(async (t) => {
            const userRef = db.collection('users').doc(userId);
            const userDoc = await t.get(userRef);

            if (userDoc.data().wallet < amount) throw new Error("Insufficient Balance");

            // Deduct immediately to lock funds
            t.update(userRef, {
                wallet: admin.firestore.FieldValue.increment(-amount)
            });

            // Create Request
            const txnRef = db.collection('transactions').doc();
            t.set(txnRef, {
                userId: userId,
                type: 'withdraw',
                amount: parseFloat(amount),
                upiId: upiId,
                status: 'Pending', // Needs Admin Approval
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: "Withdrawal requested" });

    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

/**
 * 7. ADMIN: DISTRIBUTE RESULTS
 * Complex calculation & distribution
 */
app.post('/admin/match/distribute', verifyAuth, verifyAdmin, async (req, res) => {
    const { matchId, gameUid, rank, kills } = req.body;

    if (!matchId || !gameUid) return res.status(400).json({ error: "Missing matchId or gameUid" });

    try {
        // 1. Find the Team Owner for this Game UID
        // Since we can't do complex array queries inside transaction easily without specific structure, 
        // we query first (Admin API, so slightly looser consistency is acceptable for Read, but Write must be atomic)
        
        const teamsSnapshot = await db.collection('matches').doc(matchId).collection('teams').get();
        let teamDoc = null;
        let ownerUid = null;

        teamsSnapshot.forEach(doc => {
            const data = doc.data();
            if (data.gameUids && data.gameUids.includes(gameUid)) {
                teamDoc = doc;
                ownerUid = doc.id; // Team ID is User ID in our schema
            }
        });

        if (!teamDoc) return res.status(404).json({ error: "Player not found in this match" });

        // 2. Transaction for Payout
        await db.runTransaction(async (t) => {
            const matchRef = db.collection('matches').doc(matchId);
            const userRef = db.collection('users').doc(ownerUid);
            const teamRef = matchRef.collection('teams').doc(ownerUid);

            const matchD = await t.get(matchRef);
            const teamD = await t.get(teamRef);

            if (teamD.data().hasReceivedRewards) throw new Error("Rewards already distributed to this team");

            // Calculate Prize
            const perKill = matchD.data().perKillRate || 0;
            const rankPrizes = matchD.data().rankPrizes || [];
            
            let prizeMoney = (kills * perKill);
            if (rank > 0 && rank <= rankPrizes.length) {
                prizeMoney += rankPrizes[rank - 1];
            }

            // XP Logic
            const xpEarned = (kills * 10) + (rank === 1 ? 100 : 20);

            // Writes
            if (prizeMoney > 0) {
                t.update(userRef, {
                    wallet: admin.firestore.FieldValue.increment(prizeMoney),
                    totalXP: admin.firestore.FieldValue.increment(xpEarned),
                    totalKills: admin.firestore.FieldValue.increment(kills),
                    matchesPlayed: admin.firestore.FieldValue.increment(1)
                });
                
                // Ledger
                const txnRef = db.collection('transactions').doc();
                t.set(txnRef, {
                    userId: ownerUid,
                    type: 'prize_winnings',
                    amount: prizeMoney,
                    matchId: matchId,
                    status: 'SUCCESS',
                    timestamp: admin.firestore.FieldValue.serverTimestamp()
                });
            } else {
                // Just stats update if no money won
                t.update(userRef, {
                    totalXP: admin.firestore.FieldValue.increment(xpEarned),
                    totalKills: admin.firestore.FieldValue.increment(kills),
                    matchesPlayed: admin.firestore.FieldValue.increment(1)
                });
            }

            // Mark Team processed
            t.update(teamRef, {
                hasReceivedRewards: true,
                resultRank: rank,
                resultKills: kills,
                prizeWon: prizeMoney
            });
        });

        res.json({ success: true, message: "Distributed successfully" });

    } catch (error) {
        console.error(error);
        res.status(400).json({ error: error.message });
    }
});

// --- SERVER START ---
app.listen(PORT, () => {
    console.log(`Esports Backend running on port ${PORT}`);
