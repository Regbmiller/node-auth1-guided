const express = require("express")
const bcrypt = require("bcryptjs")
const Users = require("./users-model")
const usersMiddlewaree = require("./users-middleware")

const router = express.Router()

router.get("/users", usersMiddlewaree.restrict(), async (req, res, next) => {
	try {
		res.json(await Users.find())
	} catch(err) {
		next(err)
	}
})

router.post("/users", async (req, res, next) => {
	try {
		const { username, password } = req.body
		const user = await Users.findBy({ username }).first()

		if (user) {
			return res.status(409).json({
				message: "Username is already taken",
			})
		}

		const newUser = await Users.add({
			username,
			password: await bcrypt.hash(password, 10)
		})

		res.status(201).json(newUser)
	} catch(err) {
		next(err)
	}
})

router.post("/login", async (req, res, next) => {
	try {
		const { username, password } = req.body
		const user = await Users.findBy({ username }).first()
		
		if (!user) {
			return res.status(401).json({
				message: "Invalid Credentials",
			})
		}

		//check to make sure the pw is valid
		const passwordValid = await bcrypt.compare(password, user.password)

		if (!passwordValid) {
			return res.status(401).json({
				message: "Invalid Credentials"
		})
	}
	//create a new session before sending back a new response 
		req.session.user = user
		res.json({
			message: `Welcome ${user.username}!`,
		})
	} catch(err) {
		next(err)
	}
})

router.get("/logout", usersMiddleware.restrict(), async (req, res, next) => {
	try{
		req.session.destroy((err) => {
		if (err) {
			next(err)
		} else {
			res.status(204).end()
		}
		})
	} catch (err) {
		next(err)
	}
})
module.exports = router
