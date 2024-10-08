const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db/connection');

// User Signup
exports.signup = (req, res) => {
    const { username, password, email, full_name, role } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    const query = 'INSERT INTO users (username, password, email, full_name, role) VALUES (?, ?, ?, ?, ?)';
    db.execute(query, [username, hashedPassword, email, full_name, role], (err, result) => {
        if (err) return res.status(500).send({ message: 'Database error' });
        res.status(201).send({ message: 'User registered successfully' });
    });
};

// User Login
exports.login = (req, res) => {
    const { username, password } = req.body;

    const query = 'SELECT * FROM users WHERE username = ? AND is_deleted = 0';
    db.execute(query, [username], (err, results) => {
        if (err || results.length === 0) return res.status(404).send({ message: 'User not found' });

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);

        if (!passwordIsValid) return res.status(401).send({ token: null, message: 'Invalid password' });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.status(200).send({ token, user: { username: user.username, role: user.role } });
    });
};
