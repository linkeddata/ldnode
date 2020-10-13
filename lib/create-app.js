module.exports = createApp

const express = require('express')
const session = require('express-session')
const handlebars = require('express-handlebars')
const uuid = require('uuid')
const cors = require('cors')
const LDP = require('./ldp')
const LdpMiddleware = require('./ldp-middleware')
const corsProxy = require('./handlers/cors-proxy')
const authProxy = require('./handlers/auth-proxy')
const SolidHost = require('./models/solid-host')
const AccountManager = require('./models/account-manager')
const vhost = require('vhost')
const EmailService = require('./services/email-service')
const TokenService = require('./services/token-service')
const capabilityDiscovery = require('./capability-discovery')
const API = require('./api')
const errorPages = require('./handlers/error-pages')
const config = require('./server-config')
const defaults = require('../config/defaults')
const options = require('./handlers/options')
const debug = require('./debug')
const path = require('path')
const { routeResolvedFile } = require('./utils')
const ResourceMapper = require('./resource-mapper')
const aclCheck = require('@solid/acl-check')
const { version } = require('../package.json')

const corsSettings = cors({
  methods: [
    'OPTIONS', 'HEAD', 'GET', 'PATCH', 'POST', 'PUT', 'DELETE'
  ],
  exposedHeaders: 'Authorization, User, Location, Link, Vary, Last-Modified, ETag, Accept-Patch, Accept-Post, Updates-Via, Allow, WAC-Allow, Content-Length, WWW-Authenticate, MS-Author-Via',
  credentials: true,
  maxAge: 1728000,
  origin: true,
  preflightContinue: true
})

function createApp (argv = {}) {
  // Override default configs (defaults) with passed-in params (argv)
  argv = Object.assign({}, defaults, argv)

  argv.host = SolidHost.from(argv)

  argv.resourceMapper = new ResourceMapper({
    rootUrl: argv.serverUri,
    rootPath: path.resolve(argv.root || process.cwd()),
    includeHost: argv.multiuser,
    defaultContentType: argv.defaultContentType
  })

  const configPath = config.initConfigDir(argv)
  argv.templates = config.initTemplateDirs(configPath)

  config.printDebugInfo(argv)

  const ldp = new LDP(argv)

  const app = express()

  initAppLocals(app, argv, ldp)
  initHeaders(app)
  initViews(app, configPath)
  initLoggers()

  // Serve the public 'common' directory (for shared CSS files, etc)
  app.use('/common', express.static(path.join(__dirname, '../common')))
  app.use('/', express.static(path.dirname(require.resolve('mashlib/dist/databrowser.html')), { index: false }))
  routeResolvedFile(app, '/common/js/', '@inrupt/solid-client-authn-browser/browserDist/solid-client-authn.bundle.js')
  app.use('/.well-known', express.static(path.join(__dirname, '../common/well-known')))

  // Serve bootstrap from it's node_module directory
  routeResolvedFile(app, '/common/css/', 'bootstrap/dist/css/bootstrap.min.css')
  routeResolvedFile(app, '/common/css/', 'bootstrap/dist/css/bootstrap.min.css.map')
  routeResolvedFile(app, '/common/fonts/', 'bootstrap/dist/fonts/glyphicons-halflings-regular.eot')
  routeResolvedFile(app, '/common/fonts/', 'bootstrap/dist/fonts/glyphicons-halflings-regular.svg')
  routeResolvedFile(app, '/common/fonts/', 'bootstrap/dist/fonts/glyphicons-halflings-regular.ttf')
  routeResolvedFile(app, '/common/fonts/', 'bootstrap/dist/fonts/glyphicons-halflings-regular.woff')
  routeResolvedFile(app, '/common/fonts/', 'bootstrap/dist/fonts/glyphicons-halflings-regular.woff2')

  // Serve OWASP password checker from it's node_module directory
  routeResolvedFile(app, '/common/js/', 'owasp-password-strength-test/owasp-password-strength-test.js')
  // Serve the TextEncoder polyfill
  routeResolvedFile(app, '/common/js/', 'text-encoder-lite/text-encoder-lite.min.js')

  // Add CORS proxy
  if (argv.proxy) {
    console.warn('The proxy configuration option has been renamed to corsProxy.')
    argv.corsProxy = argv.corsProxy || argv.proxy
    delete argv.proxy
  }
  if (argv.corsProxy) {
    corsProxy(app, argv.corsProxy)
  }

  // Options handler
  app.options('/*', options)

  // Set up API
  if (argv.apiApps) {
    app.use('/api/apps', express.static(argv.apiApps))
  }

  // Authenticate the user
  if (argv.webid) {
    initWebId(argv, app, ldp)
  }
  // Add Auth proxy (requires authentication)
  if (argv.authProxy) {
    authProxy(app, argv.authProxy)
  }

  // Attach the LDP middleware
  app.use('/', LdpMiddleware(corsSettings))

  // Errors
  app.use(errorPages.handler)

  return app
}

/**
 * Initializes `app.locals` parameters for downstream use (typically by route
 * handlers).
 *
 * @param app {Function} Express.js app instance
 * @param argv {Object} Config options hashmap
 * @param ldp {LDP}
 */
function initAppLocals (app, argv, ldp) {
  app.locals.ldp = ldp
  app.locals.appUrls = argv.apps // used for service capability discovery
  app.locals.host = argv.host
  app.locals.authMethod = argv.auth
  app.locals.localAuth = argv.localAuth
  app.locals.tokenService = new TokenService()
  app.locals.enforceToc = argv.enforceToc
  app.locals.tocUri = argv.tocUri
  app.locals.disablePasswordChecks = argv.disablePasswordChecks

  if (argv.email && argv.email.host) {
    app.locals.emailService = new EmailService(argv.templates.email, argv.email)
  }
}

/**
 * Sets up headers common to all Solid requests (CORS-related, Allow, etc).
 *
 * @param app {Function} Express.js app instance
 */
function initHeaders (app) {
  app.use(corsSettings)

  app.use((req, res, next) => {
    res.set('X-Powered-By', 'solid-server/' + version)

    // Cors lib adds Vary: Origin automatically, but inreliably
    res.set('Vary', 'Accept, Authorization, Origin')

    // Set default Allow methods
    res.set('Allow', 'OPTIONS, HEAD, GET, PATCH, POST, PUT, DELETE')
    next()
  })

  app.use('/', capabilityDiscovery())
}

/**
 * Sets up the express rendering engine and views directory.
 *
 * @param app {Function} Express.js app
 * @param configPath {string}
 */
function initViews (app, configPath) {
  const viewsPath = config.initDefaultViews(configPath)

  app.set('views', viewsPath)
  app.engine('.hbs', handlebars({
    extname: '.hbs',
    partialsDir: viewsPath,
    defaultLayout: null
  }))
  app.set('view engine', '.hbs')
}

/**
 * Sets up WebID-related functionality (account creation and authentication)
 *
 * @param argv {Object}
 * @param app {Function}
 * @param ldp {LDP}
 */
function initWebId (argv, app, ldp) {
  config.ensureWelcomePage(argv)

  // Store the user's session key in a cookie
  // (for same-domain browsing by people only)
  const useSecureCookies = !!argv.sslKey // use secure cookies when over HTTPS
  const sessionHandler = session(sessionSettings(useSecureCookies, argv.host))
  app.use(sessionHandler)
  // Reject cookies from third-party applications.
  // Otherwise, when a user is logged in to their Solid server,
  // any third-party application could perform authenticated requests
  // without permission by including the credentials set by the Solid server.
  app.use((req, res, next) => {
    const origin = req.get('origin')
    const trustedOrigins = ldp.getTrustedOrigins(req)
    const userId = req.session.userId
    // Exception: allow logout requests from all third-party apps
    // such that OIDC client can log out via cookie auth
    // TODO: remove this exception when OIDC clients
    // use Bearer token to authenticate instead of cookie
    // (https://github.com/solid/node-solid-server/pull/835#issuecomment-426429003)
    //
    // Authentication cookies are an optimization:
    // instead of going through the process of
    // fully validating authentication on every request,
    // we go through this process once,
    // and store its successful result in a cookie
    // that will be reused upon the next request.
    // However, that cookie can then be sent by any server,
    // even servers that have not gone through the proper authentication mechanism.
    // However, if trusted origins are enabled,
    // then any origin is allowed to take the shortcut route,
    // since malicious origins will be banned at the ACL checking phase.
    // https://github.com/solid/node-solid-server/issues/1117
    if (!argv.strictOrigin && !argv.host.allowsSessionFor(userId, origin, trustedOrigins) && !isLogoutRequest(req)) {
      debug.authentication(`Rejecting session for ${userId} from ${origin}`)
      // Destroy session data
      delete req.session.userId
      // Ensure this modified session is not saved
      req.session.save = (done) => done()
    }
    next()
  })

  const accountManager = AccountManager.from({
    authMethod: argv.auth,
    emailService: app.locals.emailService,
    tokenService: app.locals.tokenService,
    host: argv.host,
    accountTemplatePath: argv.templates.account,
    store: ldp,
    multiuser: argv.multiuser
  })
  app.locals.accountManager = accountManager

  // Account Management API (create account, new cert)
  app.use('/', API.accounts.middleware(accountManager))

  // Set up authentication-related API endpoints and app.locals
  initAuthentication(app, argv)

  if (argv.multiuser) {
    app.use(vhost('*', LdpMiddleware(corsSettings)))
  }
}

function initLoggers () {
  aclCheck.configureLogger(debug.ACL)
}

/**
 * Determines whether the given request is a logout request
 */
function isLogoutRequest (req) {
  // TODO: this is a hack that hard-codes OIDC paths,
  // this code should live in the OIDC module
  return req.path === '/logout' || req.path === '/goodbye'
}

/**
 * Sets up authentication-related routes and handlers for the app.
 *
 * @param app {Object} Express.js app instance
 * @param argv {Object} Config options hashmap
 */
function initAuthentication (app, argv) {
  const auth = argv.forceUser ? 'forceUser' : argv.auth
  if (!(auth in API.authn)) {
    throw new Error(`Unsupported authentication scheme: ${auth}`)
  }
  API.authn[auth].initialize(app, argv)
}

/**
 * Returns a settings object for Express.js sessions.
 *
 * @param secureCookies {boolean}
 * @param host {SolidHost}
 *
 * @return {Object} `express-session` settings object
 */
function sessionSettings (secureCookies, host) {
  const sessionSettings = {
    name: 'nssidp.sid',
    secret: uuid.v1(),
    saveUninitialized: false,
    resave: false,
    rolling: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000
    }
  }
  // Cookies should set to be secure if https is on
  if (secureCookies) {
    sessionSettings.cookie.secure = true
  }

  // Determine the cookie domain
  sessionSettings.cookie.domain = host.cookieDomain

  return sessionSettings
}
