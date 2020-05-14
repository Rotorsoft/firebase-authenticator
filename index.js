'use strict'

const cors = require('cors')
const admin = require('firebase-admin')
const { NODE_ENV, GOOGLE_APPLICATION_CREDENTIALS, FIREBASE_APP } = process.env
const cache = {}
let app

module.exports = options => {
  if (!GOOGLE_APPLICATION_CREDENTIALS) throw Error('Google application credentials not found')
  if (!FIREBASE_APP) throw Error('Firebase app name not found')

  const { authorizer } = options
  if (authorizer && typeof authorizer !== 'function') throw Error('Invalid authorizer in options')

  return (req, res, next) => {
    return cors(options)(req, res, async () => {
      if (options.trace) {
        const origin = req.headers.origin || req.headers['x-forwarded-for'] || req.headers['x-appengine-user-ip']
        const location = `${req.headers['x-appengine-city'] || ''} ${req.headers['x-appengine-region'] || ''} ${req.headers['x-appengine-country'] || ''}`
        console.log(`${req.hostname} received ${req.method} ${req.originalUrl} from ${origin} - ${req.ip} - ${location}`)
      }
      
      const { authorization } = req.headers

      if (!authorization) {
        res.status(403).send('Missing authorization header')
        return
      }
      if (!authorization.substr(0, 7).toLowerCase() === 'bearer ') {
        res.status(403).send('Invalid authorization header')
        return
      }

      // skip authentication when developing
      if (NODE_ENV === 'development') return next()

      app = app || admin.initializeApp({
        credential: admin.credential.applicationDefault(),
        databaseURL: `https://${FIREBASE_APP}.firebaseio.com`
      })
      const token = authorization.substr(7)
      const entry = cache[req.ip]
      const now = Date.now()

      if (entry && entry.token === token && entry.expires > now) {
        if (options.trace) console.log('Token found in cache')
        next()
      }
      else {
        delete cache[req.ip]
        try {
          const claims = await admin.auth().verifyIdToken(token, true)
          if (authorizer && !authorizer(req, claims)) {
            res.status(403).send('Request not authorized')
            return
          }
          // cache for 1hr when authenticated and authorized
          cache[req.ip] = { token, expires: now + 60 * 60 * 1000 }
          if (options.trace) console.log(`Token cached with claims ${JSON.stringify(claims)}`)
          next()
        }
        catch(error) {
          console.error(error)
          res.status(403).send('Invalid authentication token')
        }
      }
    })
  }
}
