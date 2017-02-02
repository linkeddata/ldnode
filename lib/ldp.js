var mime = require('mime-types')
var path = require('path')
var fs = require('fs-extra')
var $rdf = require('rdflib')
var async = require('async')
var uuid = require('uuid')
var debug = require('./debug')
var utils = require('./utils')
var error = require('./http-error')
var stringToStream = require('./utils').stringToStream
var serialize = require('./utils').serialize
var doWhilst = require('async').doWhilst
var ldpContainer = require('./ldp-container')
var parse = require('./utils').parse
const LdpFileStore = require('./ldp-file-store')

const DEFAULT_CONTENT_TYPE = 'text/turtle'

class LDP {
  /**
   * @constructor
   * @param [options={}] {Object}
   * @param [options.root]
   * @param [options.suffixAcl]
   * @param [options.suffixMeta]
   * @param [options.errorPages]
   * @param [options.fileBrowser]
   * @param [options.suppressDataBrowser]
   * @param [options.dataBrowserPath]
   * @param [options.webid]
   * @param [options.auth]
   * @param [options.idp]
   * @param [options.proxy]
   * @param [options.live]
   * @param [options.store]
   */
  constructor (options = {}) {
    Object.assign(this, options)

    this.suffixAcl = options.suffixAcl || '.acl'
    this.suffixMeta = options.suffixMeta || '.meta'
    this.turtleExtensions = [ '.ttl', this.suffixAcl, this.suffixMeta ]

    this.root = options.root || process.cwd()
    if (!this.root.endsWith('/')) { this.root += '/' }

    this.initErrorPages(options)

    this.store = options.store || LDP.fileStoreFromConfig(options)

    if (this.fileBrowser !== false) {
      this.fileBrowser = options.fileBrowser ||
        'https://linkeddata.github.io/warp/#/list/'
    }

    this.auth = options.auth || 'tls'

    if (this.proxy && !this.proxy.startsWith('/')) {
      this.proxy = '/' + this.proxy
    }
  }

  static fileStoreFromConfig (options) {
    let storeConfig = {
      rootPath: options.root || process.cwd(),
      idp: options.idp,
      suffixAcl: options.suffixAcl,
      suffixMeta: options.suffixMeta
    }
    return new LdpFileStore(storeConfig)
  }

  printDebugInfo () {
    debug.settings('Suffix Acl: ' + this.suffixAcl)
    debug.settings('Suffix Meta: ' + this.suffixMeta)
    debug.settings('Filesystem Root: ' + this.root)
    debug.settings('Allow WebID authentication: ' + !!this.webid)
    debug.settings('Live-updates: ' + !!this.live)
    debug.settings('Identity Provider: ' + !!this.idp)
    debug.settings('Default file browser app: ' + this.fileBrowser)
    debug.settings('Suppress default data browser app: ' + this.suppressDataBrowser)
    debug.settings('Default data browser app file path: ' + this.dataBrowserPath)
  }

  initErrorPages (options) {
    this.errorPages = null
    if (!this.noErrorPages) {
      this.errorPages = options.errorPages
      if (!this.errorPages) {
        // TODO: For now disable error pages if errorPages parameter is not explicitly passed
        this.noErrorPages = true
      } else if (!this.errorPages.endsWith('/')) {
        this.errorPages += '/'
      }
    }
  }

  delete (host, resourcePath, callback) {
    this.store
      .delete(host, resourcePath)
      .then(callback)
      .catch(error => {
        callback(error)
      })
  }

  put (host, resourcePath, stream, callback) {
    this.store
      .put(host, resourcePath, stream)
      .then(callback)
      .catch(error => {
        callback(error)
      })
  }

  stat (file, callback) {
    fs.stat(file, function (err, stats) {
      if (err) {
        return callback(error(err, "Can't read metadata"))
      }
      return callback(null, stats)
    })
  }

  createReadStream (filename, start, end) {
    if (start && end) {
      return fs.createReadStream(filename, {'start': start, 'end': end})
    } else {
      return fs.createReadStream(filename)
    }
  }

  readFile (filename, callback) {
    fs.readFile(
      filename,
      { 'encoding': 'utf8' },
      function (err, data) {
        if (err) {
          return callback(error(err, "Can't read file"))
        }
        return callback(null, data)
      })
  }

  readContainerMeta (directory, callback) {
    var ldp = this

    if (directory[ directory.length - 1 ] !== '/') {
      directory += '/'
    }

    ldp.readFile(directory + ldp.suffixMeta, function (err, data) {
      if (err) {
        return callback(error(err, "Can't read meta file"))
      }

      return callback(null, data)
    })
  }

  listContainer (filename, reqUri, uri, containerData, contentType, callback) {
    var ldp = this
    // var host = url.parse(uri).hostname
    // var root = !ldp.idp ? ldp.root : ldp.root + host + '/'

    // var baseUri = utils.filenameToBaseUri(filename, uri, root)
    var resourceGraph = $rdf.graph()

    try {
      $rdf.parse(containerData, resourceGraph, reqUri, 'text/turtle')
    } catch (err) {
      debug.handlers('GET -- Error parsing data: ' + err)
      return callback(error(500, "Can't parse container"))
    }

    async.waterfall(
      [
        // add container stats
        function (next) {
          ldpContainer.addContainerStats(ldp, reqUri, filename, resourceGraph, next)
        },
        // reading directory
        function (next) {
          ldpContainer.readdir(filename, next)
        },
        // Iterate through all the files
        function (files, next) {
          async.each(
            files,
            function (file, cb) {
              let fileUri = reqUri + encodeURIComponent(file)
              ldpContainer.addFile(ldp, resourceGraph, reqUri, fileUri, uri,
                filename, file, cb)
            },
            next)
        }
      ],
      function (err, data) {
        if (err) {
          return callback(error(500, "Can't list container"))
        }
        // TODO 'text/turtle' is fixed, should be contentType instead
        // This forces one more translation turtle -> desired
        serialize(resourceGraph, reqUri, 'text/turtle', function (err, result) {
          if (err) {
            debug.handlers('GET -- Error serializing container: ' + err)
            return callback(error(500, "Can't serialize container"))
          }
          return callback(null, result)
        })
      })
  }

  post (hostname, containerPath, slug, stream, container, callback) {
    var ldp = this
    debug.handlers('POST -- On parent: ' + containerPath)
    // prepare slug
    if (slug) {
      slug = decodeURIComponent(slug)
      if (slug.match(/\/|\||:/)) {
        callback(error(400, 'The name of new file POSTed may not contain : | or /'))
        return
      }
    }
    // TODO: possibly package this in ldp.post
    ldp.getAvailablePath(hostname, containerPath, slug, function (resourcePath) {
      debug.handlers('POST -- Will create at: ' + resourcePath)
      let originalPath = resourcePath
      if (container) {
        // Create directory by an LDP PUT to the container's .meta resource
        resourcePath = path.join(originalPath, ldp.suffixMeta)
        if (originalPath && !originalPath.endsWith('/')) {
          originalPath += '/'
        }
      }
      ldp.put(hostname, resourcePath, stream, function (err) {
        if (err) callback(err)
        callback(null, originalPath)
      })
    })
  }

  exists (host, reqPath, callback) {
    var options = {
      'hostname': host,
      'path': reqPath,
      'baseUri': undefined,
      'includeBody': false,
      'possibleRDFType': undefined
    }
    this.get(options, callback)
  }

  graph (host, reqPath, baseUri, contentType, callback) {
    var ldp = this

    // overloading
    if (typeof contentType === 'function') {
      callback = contentType
      contentType = 'text/turtle'
    }

    if (typeof baseUri === 'function') {
      callback = baseUri
      baseUri = undefined
    }

    var root = ldp.idp ? ldp.root + host + '/' : ldp.root
    var filename = utils.uriToFilename(reqPath, root)

    async.waterfall([
      // Read file
      function (cb) {
        return ldp.readFile(filename, cb)
      },
      // Parse file
      function (body, cb) {
        parse(body, baseUri, contentType, function (err, graph) {
          cb(err, graph)
        })
      }
    ], callback)
  }

  // handler: ldp.get(options, function (err, ret) {
  /**
   * @param options {Object}
   * @param options.hostname {string} req.hostname
   * @param options.path {string}
   * @param options.baseUri {string}
   * @param options.includeBody {Boolean}
   * @param options.possibleRDFType {string}
   * @param callback {Function}
   */
  get (options, callback) {
    options = options || {}
    let host = options.hostname
    let reqPath = options.path
    let baseUri = options.baseUri
    let includeBody = options.includeBody
    let contentType = options.possibleRDFType
    let range = options.range

    // this.store
    //   .findResource(options.hostname, options.path)
    //   .then(resource => {
    //     if (!resource.fileExists) {
    //       throw error(404, 'Can\'t find file requested: ' + resource.filename)
    //     }
    //   })
    //   .catch(err => {
    //     callback(err)
    //   })

    var ldp = this
    var root = !ldp.idp ? ldp.root : ldp.root + host + '/'

    var filename = utils.uriToFilename(reqPath, root)

    ldp.stat(filename, function (err, stats) {
      // File does not exist
      if (err) {
        return callback(error(err, 'Can\'t find file requested: ' + filename))
      }

      // Just return, since resource exists
      if (!includeBody) {
        return callback(null, {'stream': stats, 'contentType': contentType, 'container': stats.isDirectory()})
      }

      // Found a container
      if (stats.isDirectory()) {
        return ldp.readContainerMeta(filename, function (err, metaFile) {
          if (err) {
            metaFile = ''
          }
          let absContainerUri = baseUri + reqPath
          ldp.listContainer(filename, absContainerUri, baseUri, metaFile, contentType,
            function (err, data) {
              if (err) {
                debug.handlers('GET container -- Read error:' + err.message)
                return callback(err)
              }
              var stream = stringToStream(data)
              // TODO 'text/turtle' is fixed, should be contentType instead
              // This forces one more translation turtle -> desired
              return callback(null, {'stream': stream, 'contentType': 'text/turtle', 'container': true})
            })
        })
      } else {
        var stream
        if (range) {
          var total = fs.statSync(filename).size
          var parts = range.replace(/bytes=/, '').split('-')
          var partialstart = parts[0]
          var partialend = parts[1]
          var start = parseInt(partialstart, 10)
          var end = partialend ? parseInt(partialend, 10) : total - 1
          var chunksize = (end - start) + 1
          var contentRange = 'bytes ' + start + '-' + end + '/' + total
          stream = ldp.createReadStream(filename, start, end)
        } else {
          stream = ldp.createReadStream(filename)
        }
        stream
          .on('error', function (err) {
            debug.handlers('GET -- Read error:' + err.message)
            return callback(error(err, "Can't create file " + err))
          })
          .on('open', function () {
            debug.handlers('GET -- Read Start.')
            var contentType = mime.lookup(filename) || DEFAULT_CONTENT_TYPE
            if (utils.hasSuffix(filename, ldp.turtleExtensions)) {
              contentType = 'text/turtle'
            }
            return callback(null, {'stream': stream, 'contentType': contentType, 'container': false, 'contentRange': contentRange, 'chunksize': chunksize})
          })
      }
    })
  }

  getAvailablePath (host, containerURI, slug, callback) {
    var self = this
    var exists

    if (!slug) {
      slug = uuid.v1()
    }

    var newPath = path.join(containerURI, slug)

    // TODO: maybe a nicer code
    doWhilst(
      function (next) {
        self.exists(host, newPath, function (err) {
          exists = !err

          if (exists) {
            var id = uuid.v1().split('-')[ 0 ] + '-'
            newPath = path.join(containerURI, id + slug)
          }

          next()
        })
      },
      function () {
        return exists === true
      },
      function () {
        callback(newPath)
      })
  }
}
module.exports = LDP
