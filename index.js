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
    const origin = req.headers.origin || req.origin || req.headers['x-forwarded-for'] || req.headers['x-appengine-user-ip']
    const location = `${req.headers['x-appengine-city']}, ${req.headers['x-appengine-region']} ${req.headers['x-appengine-country']}`

    if (options.trace) console.log(`${req.hostname} received request from ${origin} ${location}`)
    
    if (!cors || req.hostname === origin) {
      // skip when developing or request is coming from same host in cloud
      next()
    }
    else {
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

        const token = authorization.substr(7)
        app = app || admin.initializeApp()

        if (cache[req.ip] === token) {
          if (options.trace) console.log(`Token for IP ${req.ip} found in cache`)
          next()
        }
        else {
          admin.auth().verifyIdToken(token, true)
            .then(claims => {
              if (options.trace) console.log(`Token for IP ${req.ip} added to cache with claims ${JSON.stringify(claims)}`)
              
              if (authorizer && !authorizer(claims)) {
                res.status(403).send('Request not authorized')
                return
              }

              // authenticated and authorized
              cache[req.ip] = token
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
