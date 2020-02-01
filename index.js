'use strict'

require('dotenv').config()
const cors = require('cors')
const admin = require('firebase-admin')

const authenticate = (process.env.NODE_ENV !== 'development')

const cache = {}
if (authenticate) admin.initializeApp()
else console.log('firebase-authenticator middleware running in development mode')

module.exports = options => {
  return (req, res, next) => {
    return cors(options)(req, res, () => {
      if (authenticate) {
        const auth = req.headers.authorization
        if (!auth) res.status(403).send('Missing authorization header')
        if (!auth.substr(0, 7).toLowerCase() === 'bearer ') res.status(403).send('Invalid authorization header')
        const token = auth.substr(7)

        if (cache[req.ip] === token) {
          if (options.trace) console.log(`Token for IP ${req.ip} found in cache`)
          next()
        }
        else {
          admin.auth().verifyIdToken(token, true).then(() => {
            cache[req.ip] = token
            if (options.trace) console.log(`Token for IP ${req.ip} added to cache`)
            next()
          }).catch(() => {
            res.status(403).send('Invalid authentication token')
          })
        }
      }
      else {
        next()
      }
    })
  }
}
