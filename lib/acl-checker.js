'use strict'
/* eslint-disable node/no-deprecated-api */

const { dirname } = require('path')
const rdf = require('rdflib')
const debug = require('./debug').ACL
const debugCache = require('./debug').cache
const HTTPError = require('./http-error')
const aclCheck = require('@solid/acl-check')
const { URL } = require('url')
const { promisify } = require('util')
const fs = require('fs')
const Url = require('url')
const httpFetch = require('node-fetch')

const DEFAULT_ACL_SUFFIX = '.acl'
const ACL = rdf.Namespace('http://www.w3.org/ns/auth/acl#')

// TODO: expunge-on-write so that we can increase the caching time
// For now this cache is a big performance gain but very simple
// FIXME: set this through the config system instead of directly
// through an env var:
const EXPIRY_MS = parseInt(process.env.ACL_CACHE_TIME) || 10000 // 10 seconds
let temporaryCache = {}

// An ACLChecker exposes the permissions on a specific resource
class ACLChecker {
  constructor (resource, options = {}) {
    this.resource = resource
    this.resourceUrl = new URL(resource)
    this.agentOrigin = options.strictOrigin && options.agentOrigin ? rdf.sym(options.agentOrigin) : null
    this.fetch = options.fetch
    this.fetchGraph = options.fetchGraph
    this.trustedOrigins = options.strictOrigin && options.trustedOrigins ? options.trustedOrigins.map(trustedOrigin => rdf.sym(trustedOrigin)) : null
    this.suffix = options.suffix || DEFAULT_ACL_SUFFIX
    this.aclCached = {}
    this.messagesCached = {}
    this.requests = {}
    this.slug = options.slug
    this.hasPaid = options.hasPaid
  }

  // Returns a fulfilled promise when the user can access the resource
  // in the given mode; otherwise, rejects with an HTTP error
  async can (user, mode, method = 'GET', resourceExists = true) {
    const cacheKey = `${mode}-${user}`
    if (this.aclCached[cacheKey]) {
      return this.aclCached[cacheKey]
    }
    this.messagesCached[cacheKey] = this.messagesCached[cacheKey] || []

    const acl = await this.getNearestACL().catch(err => {
      this.messagesCached[cacheKey].push(new HTTPError(err.status || 500, err.message || err))
    })
    if (!acl) {
      this.aclCached[cacheKey] = Promise.resolve(false)
      return this.aclCached[cacheKey]
    }
    let resource = rdf.sym(this.resource)
    if (this.resource.endsWith('/' + this.suffix)) {
      resource = rdf.sym(ACLChecker.getDirectory(this.resource))
    }
    // If this is an ACL, Control mode must be present for any operations
    if (this.isAcl(this.resource)) {
      mode = 'Control'
      resource = rdf.sym(this.resource.substring(0, this.resource.length - this.suffix.length))
    }
    // If the slug is an acl, reject
    /* if (this.isAcl(this.slug)) {
      this.aclCached[cacheKey] = Promise.resolve(false)
      return this.aclCached[cacheKey]
    } */
    const directory = acl.isContainer ? rdf.sym(ACLChecker.getDirectory(acl.acl)) : null
    const aclFile = rdf.sym(acl.acl)
    const agent = user ? rdf.sym(user) : null
    const modes = [ACL(mode)]
    const agentOrigin = this.agentOrigin
    const trustedOrigins = this.trustedOrigins
    let originTrustedModes = []
    let payingWouldHelp = false
    try {
      this.fetch(aclFile.doc().value)
      originTrustedModes = await aclCheck.getTrustedModesForOrigin(acl.graph, resource, directory, aclFile, agentOrigin, (uriNode) => {
        return this.fetch(uriNode.doc().value, acl.graph)
      })
    } catch (e) {
      // FIXME: https://github.com/solid/acl-check/issues/23
      // console.error(e.message)
    }
    let accessDenied = aclCheck.accessDenied(acl.graph, resource, directory, aclFile, agent, modes, agentOrigin, trustedOrigins, originTrustedModes, () => {
      const currentPaid = this.hasPaid()
      if (!currentPaid) {
        payingWouldHelp = true
      }
      return currentPaid
    })

    // For create and update HTTP methods
    if ((method === 'PUT' || method === 'PATCH' || method === 'COPY') && directory) {
      // if resource and acl have same parent container,
      // and resource does not exist, then accessTo Append from parent is required
      if (directory.value === dirname(aclFile.value) + '/' && !resourceExists) {
        const accessDeniedAccessTo = aclCheck.accessDenied(acl.graph, directory, null, aclFile, agent, [ACL('Append')], agentOrigin, trustedOrigins, originTrustedModes, () => {
          const currentPaid = this.hasPaid()
          if (!currentPaid) {
            payingWouldHelp = true
          }
          return currentPaid
        })
        const accessResult = !accessDenied && !accessDeniedAccessTo
        accessDenied = accessResult ? false : accessDenied || accessDeniedAccessTo
        // debugCache('accessDenied result ' + accessDenied)
      }
    }
    if (accessDenied && payingWouldHelp) {
      this.messagesCached[cacheKey].push(HTTPError(402, 'Payment Required'))
    } else if (accessDenied && user) {
      this.messagesCached[cacheKey].push(HTTPError(403, accessDenied))
    } else if (accessDenied) {
      this.messagesCached[cacheKey].push(HTTPError(401, 'Unauthenticated'))
    }
    this.aclCached[cacheKey] = Promise.resolve(!accessDenied)
    return this.aclCached[cacheKey]
  }

  async getError (user, mode) {
    const cacheKey = `${mode}-${user}`
    // TODO ?? add to can: req.method and resourceExists.  Actually all tests pass
    this.aclCached[cacheKey] = this.aclCached[cacheKey] || this.can(user, mode)
    const isAllowed = await this.aclCached[cacheKey]
    return isAllowed ? null : this.messagesCached[cacheKey].reduce((prevMsg, msg) => msg.status > prevMsg.status ? msg : prevMsg, { status: 0 })
  }

  static getDirectory (aclFile) {
    const parts = aclFile.split('/')
    parts.pop()
    return `${parts.join('/')}/`
  }

  // Gets the ACL that applies to the resource
  async getNearestACL () {
    const { resource } = this
    let isContainer = false
    const possibleACLs = this.getPossibleACLs()
    const acls = [...possibleACLs]
    let returnAcl = null
    while (possibleACLs.length > 0 && !returnAcl) {
      const acl = possibleACLs.shift()
      let graph
      try {
        this.requests[acl] = this.requests[acl] || this.fetch(acl)
        graph = await this.requests[acl]
      } catch (err) {
        if (err && (err.code === 'ENOENT' || err.status === 404)) {
          isContainer = true
          continue
        }
        debug(err)
        throw err
      }
      const relative = resource.replace(acl.replace(/[^/]+$/, ''), './')
      debug(`Using ACL ${acl} for ${relative}`)
      returnAcl = { acl, graph, isContainer }
    }
    if (!returnAcl) {
      throw new HTTPError(500, `No ACL found for ${resource}, searched in \n- ${acls.join('\n- ')}`)
    }
    const groupNodes = returnAcl.graph.statementsMatching(null, ACL('agentGroup'), null)
    const groupUrls = groupNodes.map(node => node.object.value.split('#')[0])
    await Promise.all(groupUrls.map(async groupUrl => {
      try {
        const graph = await this.fetch(groupUrl, returnAcl.graph)
        this.requests[groupUrl] = this.requests[groupUrl] || graph
      } catch (e) {} // failed to fetch groupUrl
    }))

    return returnAcl
  }

  // Gets all possible ACL paths that apply to the resource
  getPossibleACLs () {
    // Obtain the resource URI and the length of its base
    const { resource: uri, suffix } = this
    const [{ length: base }] = uri.match(/^[^:]+:\/*[^/]+/)

    // If the URI points to a file, append the file's ACL
    const possibleAcls = []
    if (!uri.endsWith('/')) {
      possibleAcls.push(uri.endsWith(suffix) ? uri : uri + suffix)
    }

    // Append the ACLs of all parent directories
    for (let i = lastSlash(uri); i >= base; i = lastSlash(uri, i - 1)) {
      possibleAcls.push(uri.substr(0, i + 1) + suffix)
    }
    return possibleAcls
  }

  isAcl (resource) {
    return resource.endsWith(this.suffix)
  }

  static createFromLDPAndRequest (resource, ldp, req, hasPaid) {
    const trustedOrigins = ldp.getTrustedOrigins(req)
    return new ACLChecker(resource, {
      agentOrigin: req.get('origin'),
      // host: req.get('host'),
      fetch: fetchLocalOrRemote(ldp.resourceMapper, ldp.serverUri),
      fetchGraph: (uri, options) => {
        // first try loading from local fs
        return ldp.getGraph(uri, options.contentType)
        // failing that, fetch remote graph
          .catch(() => ldp.fetchGraph(uri, options))
      },
      suffix: ldp.suffixAcl,
      strictOrigin: ldp.strictOrigin,
      trustedOrigins,
      hasPaid,
      slug: decodeURIComponent(req.headers.slug)
    })
  }
}

/**
 * Returns a fetch document handler used by the ACLChecker to fetch .acl
 * resources up the inheritance chain.
 * The `fetch(uri, callback)` results in the callback, with either:
 *   - `callback(err, graph)` if any error is encountered, or
 *   - `callback(null, graph)` with the parsed RDF graph of the fetched resource
 * @return {Function} Returns a `fetch(uri, callback)` handler
 */
function fetchLocalOrRemote (mapper, serverUri) {
  async function doFetch (url) {
    // Convert the URL into a filename
    let body, path, contentType

    if (Url.parse(url).host.includes(Url.parse(serverUri).host)) {
      // Fetch the acl from local
      try {
        ({ path, contentType } = await mapper.mapUrlToFile({ url }))
      } catch (err) {
        // delete from cache
        delete temporaryCache[url]
        throw new HTTPError(404, err)
      }
      // Read the file from disk
      body = await promisify(fs.readFile)(path, { encoding: 'utf8' })
    } else {
      // Fetch the acl from the internet
      const response = await httpFetch(url)
      body = await response.text()
      contentType = response.headers.get('content-type')
    }
    return { body, contentType }
  }
  return async function fetch (url, graph = rdf.graph()) {
    graph.initPropertyActions(['sameAs']) // activate sameAs
    if (!temporaryCache[url]) {
      // debugCache('Populating cache', url)
      temporaryCache[url] = {
        timer: setTimeout(() => {
          // debugCache('Expunging from cache', url)
          delete temporaryCache[url]
          if (Object.keys(temporaryCache).length === 0) {
            debugCache('Cache is empty again')
          }
        }, EXPIRY_MS),
        promise: doFetch(url)
      }
    }
    // debugCache('Cache hit', url)
    const { body, contentType } = await temporaryCache[url].promise
    // Parse the file as Turtle
    rdf.parse(body, graph, url, contentType)
    return graph
  }
}

// Returns the index of the last slash before the given position
function lastSlash (string, pos = string.length) {
  return string.lastIndexOf('/', pos)
}

module.exports = ACLChecker
module.exports.DEFAULT_ACL_SUFFIX = DEFAULT_ACL_SUFFIX

// Used in ldp and the unit tests:
module.exports.clearAclCache = function (url) {
  if (url) delete temporaryCache[url]
  else temporaryCache = {}
}
