const {Router} = require('express');
const router = Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const {check, validationResult} = require('express-validator');

// /api/auth/register
router.post(
	'/register',
	[
		check('email', "Invaild email").isEmail(),
		check('password', "Minimal password length is 8 symbols")
		.isLength({ min: 8 })
	],
	async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return res.status(400).json({
					errors: errors.array(),
					message: "Invalid registration credentials"
				})
			}
			const {email, password} = req.body;
			const candidate = await User.findOne({ email });
			if (candidate) {
				return res.status(400).json({ message: "User already exists" });
			}
			const hashedPassword = await bcrypt.hash(password, 12);
			const user = new User({ email, password: hashedPassword });
			await user.save();
			res.status(201).json({ message: "User has been created" });
		}
		catch (e) {
			res.status(500).json({ message: "Something's going wrong" });
		}
});

// /api/auth/login
router.post(
	'/login',
	[
		check('email', "Enter correct email").normalizeEmail().isEmail(),
		check('password', "Enter the password").exists()
	],
	async (req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return res.status(400).json({
					errors: errors.array(),
					message: "Invalid login credentials"
				})
			}
			const {email, password} = req.body;
			const user = await User.findOne({ email });
			if (!user) {
				return res.status(400).json({ message: "User is not found" });
			}
			const isMatch = await bcrypt.compare(password, user.password);
			if (!isMatch) {
				return res.status(400).json({ message: "Wrong password" });
			}
			const token = jwt.sign(
				{ userId: user.id },
				config.get("jwtSecret"),
				{ expiresIn: "1h" }
			);
			res.json({ token, userId: user.id });
		}
		catch (e) {
			res.status(500).json({ message: "Something's going wrong" });
		}
});

module.exports = router;