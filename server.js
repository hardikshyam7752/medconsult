const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Simple auth (users saved in users.json) ---------- */
const DB = path.join(__dirname, 'users.json');
const users = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB, 'utf8')) : {};
const saveUsers = () => fs.writeFileSync(DB, JSON.stringify(users, null, 2));
const sessions = {}; // token -> { username, role }
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');

app.post('/api/register', (req, res) => {
    const { username, password, role } = req.body || {};
    if (!/^[\w.-]{2,30}$/.test(username || ''))
        return res.status(400).json({ error: 'Username: 2-30 letters, numbers, . _ -' });
    if (!password || password.length < 4)
        return res.status(400).json({ error: 'Password must be at least 4 characters' });
    if (!['patient', 'doctor'].includes(role))
        return res.status(400).json({ error: 'Invalid role' });
    if (users[username]) return res.status(409).json({ error: 'Username already exists' });
    const salt = crypto.randomBytes(16).toString('hex');
    users[username] = { salt, hash: hashPw(password, salt), role };
    saveUsers();
    res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
    const { username, password, role } = req.body || {};
    const u = users[username];
    if (!u) return res.status(401).json({ error: 'No such account. Please sign up first.' });
    if (u.hash !== hashPw(password || '', u.salt)) return res.status(401).json({ error: 'Wrong password' });
    if (u.role !== role) return res.status(403).json({ error: `This account is registered as ${u.role}, not ${role}` });
    const token = crypto.randomUUID();
    sessions[token] = { username, role: u.role };
    res.json({ token, username, role: u.role });
});

// STUN always; TURN only if you set env vars TURN_URL, TURN_USER, TURN_PASS
app.get('/api/ice', (req, res) => {
    const servers = [{ urls: 'stun:stun.l.google.com:19302' }];
    if (process.env.TURN_URL) {
        servers.push({
            urls: process.env.TURN_URL.split(',').map((s) => s.trim()),
            username: process.env.TURN_USER,
            credential: process.env.TURN_PASS,
        });
    }
    res.json(servers);
});

/* ---------- Signaling (Socket.IO) ---------- */
const doctors = new Map(); // socket.id -> socket (online doctors)
const peer = new Map();    // socket.id -> other socket (patient <-> doctor in a call)
const ringing = new Map(); // patient socket.id -> Set of doctor socket.ids being rung

io.use((socket, next) => {
    const s = sessions[socket.handshake.auth.token];
    if (!s) return next(new Error('unauthorized'));
    socket.data = s;
    next();
});

const sock = (id) => io.sockets.sockets.get(id);

function broadcastCount() {
    const free = [...doctors.values()].filter((d) => !peer.has(d.id)).length;
    io.emit('doctor-count', free);
}

function failIfNobodyLeft(patientId, reason) {
    const set = ringing.get(patientId);
    if (set && set.size === 0) {
        ringing.delete(patientId);
        sock(patientId)?.emit('call-failed', reason);
    }
}

// patient cancelled / left while ringing: stop ringing all doctors
function cancelRinging(patientId) {
    const set = ringing.get(patientId);
    if (!set) return;
    ringing.delete(patientId);
    set.forEach((did) => sock(did)?.emit('call-gone', { userId: patientId }));
}

// doctor became busy / left: remove them from every ringing set
function dropDoctorFromRinging(doctorId) {
    for (const [pid, set] of ringing) {
        if (set.delete(doctorId)) {
            sock(doctorId)?.emit('call-gone', { userId: pid });
            failIfNobodyLeft(pid, 'All doctors are busy right now. Please try again shortly.');
        }
    }
}

function endCall(socket) {
    const other = peer.get(socket.id);
    if (!other) return;
    peer.delete(socket.id);
    peer.delete(other.id);
    other.emit('hangup');
    broadcastCount();
}

io.on('connection', (socket) => {
    const { username, role } = socket.data;
    if (role === 'doctor') doctors.set(socket.id, socket);
    broadcastCount();

    // PATIENT: ring ALL free doctors
    socket.on('call-request', () => {
        if (role !== 'patient' || peer.has(socket.id) || ringing.has(socket.id)) return;
        const free = [...doctors.values()].filter((d) => !peer.has(d.id));
        if (!free.length)
            return socket.emit('call-failed', 'No doctor is available right now. Please try again shortly.');
        ringing.set(socket.id, new Set(free.map((d) => d.id)));
        free.forEach((d) => d.emit('incoming-call', { userId: socket.id, from: username }));
        socket.emit('ringing');
    });

    // DOCTOR: first one to accept gets the call
    socket.on('call-accept', ({ userId } = {}) => {
        const patient = sock(userId);
        const set = ringing.get(userId);
        if (role !== 'doctor' || !patient || !set || !set.has(socket.id) || peer.has(socket.id))
            return socket.emit('call-gone', { userId });

        ringing.delete(userId);
        set.forEach((did) => { if (did !== socket.id) sock(did)?.emit('call-gone', { userId }); });

        peer.set(socket.id, patient);
        peer.set(patient.id, socket);
        dropDoctorFromRinging(socket.id); // this doctor is busy now
        patient.emit('call-accepted', { doctor: username });
        broadcastCount();
    });

    socket.on('call-reject', ({ userId } = {}) => {
        const set = ringing.get(userId);
        if (set && set.delete(socket.id)) failIfNobodyLeft(userId, 'No doctor accepted the call.');
    });

    // WebRTC messages: just relay to the other side
    socket.on('offer', (d) => peer.get(socket.id)?.emit('offer', d));
    socket.on('answer', (d) => peer.get(socket.id)?.emit('answer', d));
    socket.on('ice', (d) => peer.get(socket.id)?.emit('ice', d));

    socket.on('hangup', () => {
        if (peer.has(socket.id)) endCall(socket);
        else cancelRinging(socket.id);
    });

    socket.on('disconnect', () => {
        doctors.delete(socket.id);
        cancelRinging(socket.id);
        dropDoctorFromRinging(socket.id);
        endCall(socket);
        broadcastCount();
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Open http://localhost:${PORT}`));