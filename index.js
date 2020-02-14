'use strict'

require('dotenv').config()

let cors, admin, app, cache

if (process.env.NODE_ENV === 'development') {
  console.log('firebase-authenticator middleware running in development mode')
}
else {
  cors = require('cors')
  admin = require('firebase-admin')
  cache = {}
}

module.exports = options => {
  const { authorizer } = options
  if (authorizer && typeof authorizer !== 'function') throw Error('Invalid authorizer in options')

  return (req, res, next) => {
    if (!cors) next() // skip when developing
    else {
      if (options.trace) {
        const origin = req.headers.origin || req.headers['x-forwarded-for'] || req.headers['x-appengine-user-ip']
        const location = `${req.headers['x-appengine-city']}, ${req.headers['x-appengine-region']} ${req.headers['x-appengine-country']}`
        console.log(`${req.hostname} received request from ${origin} - ${req.ip} - ${location}`)
      }
      return cors(options)(req, res, () => {
        const { authorization } = req.headers

        if (!authorization) {
          res.status(403).send('Missing authorization header')
          return
        }
        if (!authorization.substr(0, 7).toLowerCase() === 'bearer ') {
          res.status(403).send('Invalid authorization header')
          return
        }

        app = app || admin.initializeApp()
        const token = authorization.substr(7)
        const entry = cache[req.ip]
        const now = Date.now()

        if (entry && entry.token === token && entry.expires > now) {
          if (options.trace) console.log('Token found in cache')
          next()
        }
        else {
          delete cache[req.ip]

          admin.auth().verifyIdToken(token, true)
            .then(claims => {
              if (authorizer && !authorizer(req, claims)) {
                res.status(403).send('Request not authorized')
                return
              }

              // cache for 1hr when authenticated and authorized
              cache[req.ip] = { token, expires: now + 60 * 60 * 1000 }
              if (options.trace) console.log(`Token cached with claims ${JSON.stringify(claims)}`)
              next()
            })
            .catch(() => {
              res.status(403).send('Invalid authentication token')
            })
        }
      })
    }
  }
}
