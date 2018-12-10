const request = require('request')
const crypto = require('crypto')
const url = require('url')
const qs = require('querystring')
const fs = require('fs')

const isJSON = json => {
  try {
    return JSON.parse(json)
  }
  catch (e) {
    return false
  }
}

const API = 'https://api.opskins.com'
const VERSION = 'v1'

const AUTH = `https://oauth.opskins.com/${VERSION}/authorize`
const ACCESS_TOKEN = `https://oauth.opskins.com/${VERSION}/access_token`

const URL = {
  // IOAuth
  CreateClient: `${API}/IOAuth/CreateClient/${VERSION}/`,
  DeleteClient: `${API}/IOAuth/DeleteClient/${VERSION}/`,
  GetOwnedClientList: `${API}/IOAuth/GetOwnedClientList/${VERSION}/`,
  // IUser
  GetProfile: `${API}/IUser/GetProfile/${VERSION}/`
}

const Strategy = function (options = {}, callback = Function()) {
  if (!options.name || !options.returnURL || !options.apiKey) {
    throw new Error('Missing required name, returnURL or apiKey parameter.')
  }

  Object.assign(this, options)

  this.apiKey = Buffer.from(`${this.apiKey}:`, 'ascii').toString('base64')
  this.siteName = this.name
  this.scopes = this.scopes || 'identity'
  this.states = []
  
  this.qs = {}
  if (this.mobile) this.qs.mobile = 1
  if (this.permanent) this.qs.duration = 'permanent'

  this.clientID = null
  this.clientSecret = null

  this.name = 'opskins'
  this.callback = callback

  this.setClientValues = (id, secret) => {
    this.clientID = id
    this.clientSecret = secret
  }

  this.createClient = () => {
    return new Promise((resolve, reject) => {
      request.post({
        url: URL.CreateClient,
        headers: {
          'authorization': `Basic ${this.apiKey}`, 
          'content-type': 'application/json; charset=utf-8'
        },
        body: JSON.stringify({
          name: this.siteName,
          redirect_uri: this.returnURL
        })
      }, (err, res, body) => {
        if (err) return reject(err)

        const json = isJSON(body)
        if (!json) return reject(`Invalid JSON response while trying to get owned client list.`)

        if (json.status !== 1) return reject(`Error while trying to create a client. (${json.message || json.status})`)

        if (!json.response || !json.response.client || !json.response.client.client_id || !json.response.secret) {
          return reject(json.message)
        }

        resolve(json.response)
      })
    })
  }

  this.deleteClient = client => {
    request.post({
      url: URL.DeleteClient,
      headers: {
        'authorization': `Basic ${this.apiKey}`,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: `client_id=${client}`
    }, (err, res, body) => {
      if (err) console.log(err, body)
    })
  }

  this.getClients = () => {
    return new Promise((resolve, reject) => {
      request.get({
        url: URL.GetOwnedClientList,
        headers: {
          'authorization': `Basic ${this.apiKey}`,
          'content-type': 'application/json; charset=utf-8'
        }
      }, (err, res, body) => {
        if (err) return reject(err)

        const json = isJSON(body)
        if (!json) return reject(`Invalid JSON response while trying to get owned client list.`)

        if (json.status !== 1) return reject(`Error while trying to get owned client list. (${json.message || json.status})`)

        resolve(json.response.clients)
      })
    })
  }

  // this is a callback function cause I can't be arsed to
  // catch any errors
  this.loadClient = (callback = Function()) => {
    // Load all clients that have been created
    this.getClients()
      .then(clients => {
        // check if client id file exists
        if (fs.existsSync('./opskins.json')) {
          const client = JSON.parse(fs.readFileSync('./opskins.json'))
          // check if client exists on opskins
          const exists = clients.find(x => x.client_id === client.client_id)
          // set client values if it's present on opskins
          if (exists) {
            this.setClientValues(client.client_id, client.secret)
            // cb
            return callback()
          }
        }
        // either the file with client id doesn't exist or it's missing on opskins
        this.createClient()
          .then(data => {
            // set client values
            this.setClientValues(data.client.client_id, data.secret)
            // write client to file
            fs.writeFileSync('./opskins.json', JSON.stringify({
              client_id: data.client.client_id,
              secret: data.secret
            }))
            // cb
            return callback()
          })
          .catch(err => {
            console.error(err)
            // cb
            return callback(err)
          })
      })
  }
  // Load client on init
  this.loadClient()

  this.setStates = states => {
    this.states = states
  }

  this.login = () => {
    const state = crypto.randomBytes(8).toString('hex')
    this.states.push(state)

    setTimeout(() => {
      for (const index in this.states) {
        if (this.states[index] === state) this.states.splice(index, 1)
      }
    }, 600000) // 10 min

    const QUERYSTRING = qs.stringify({
      response_type: 'code',
      state,
      client_id: this.clientID,
      scope: this.scopes,
      ...this.qs
    })

    return `${AUTH}?${QUERYSTRING}`
  }

  this.getProfile = accessToken => {
    return new Promise((resolve, reject) => {
      request.get({
        url: URL.GetProfile,
        headers: {
          'authorization': `Bearer ${accessToken}`
        }
      }, (err, res, body) => {
        if (err) return reject(err)

        const json = isJSON(body)
        if (!json) return reject(`Invalid JSON response while trying to get user profile.`)

        if (json.error) {
          console.error(`Error while trying to get user profile: ${json.error}`)
          return reject(json.error)
        }

        resolve(json)
      })
    })
  }

  this.getAccessToken = query => {
    return new Promise((resolve, reject) => {
      const authBuffer = Buffer.from(`${this.clientID}:${this.clientSecret}`).toString('base64')
      request.post({
        url: ACCESS_TOKEN,
        headers: {
          'authorization': `Basic ${authBuffer}`,
          'content-type': 'application/x-www-form-urlencoded'
        },
        body: `grant_type=authorization_code&code=${query.code}`
      }, (err, res, body) => {
        if (err) {
          console.error(err)
          return reject(err)
        }
  
        const json = isJSON(body)
        if (!json) {
          console.error(`Invalid JSON response`)
          return reject(`Invalid JSON response`)
        }
  
        if (json.error) {
          console.error(
            `Error with authentication: ${json.error}`,
            `client_id: ${this.clientID}`,
            `client_secret: ${this.clientSecret}`,
            `query: ${JSON.stringify(query)}`
          )
          return reject(json.error)
        }
  
        resolve(json)
      })
    })
  }

  const self = this
  this.authenticate = function (data, redirect) {
    const urlOptions = data._parsedUrl

    if (url.parse(self.returnURL).pathname !== urlOptions.pathname) {
      data.res.redirect(self.login())
    } else {
      const query = qs.parse(urlOptions.query)

      if (self.states.indexOf(query.state) === -1) {
        const err = new Error('Authentication did not originate from this server.')
        console.error(err)
        return this.fail(err)
      }

      self.getAccessToken(query)
        .then(json => {
          return Promise.all([self.getProfile(json.access_token), json])
        })
        .then(results => {
          const user = results[0].response
          const access = results[1]
          
          user.access = access
          user.access.code = query.code 

          self.callback(user, (err, data) => {
            if (err) {
              return this.fail(err)
            }

            this.success(data)
          })
        })
        .catch(err => {
          this.fail(err)
        })
    }
  }

  this.refreshAccessToken = refreshToken => {
    return new Promise((resolve, reject) => {
      const authBuffer = Buffer.from(`${this.clientID}:${this.clientSecret}`).toString('base64')

      request.post({
        url: ACCESS_TOKEN,
        headers: {
          'authorization': `Basic ${authBuffer}`,
          'content-type': 'application/x-www-form-urlencoded'
        },
        body: `grant_type=refresh_token&refresh_token=${refreshToken}`
      }, (err, res, body) => {
        if (err) {
          console.error(err)
          return reject(err)
        }
  
        const json = isJSON(body)
        if (!json) {
          console.error(`Invalid JSON response`)
          return reject(`Invalid JSON response`)
        }
  
        if (json.error) {
          console.error(
            `Error with refresh token request: ${json.error}`,
            `client_id: ${this.clientID}`,
            `client_secret: ${this.clientSecret}`,
            `code: ${query.code}`
          )
          return reject(json.error)
        }

        resolve(json.access_token)
      })
    })
  }
}

module.exports = { Strategy }