function getIlpStreamPayParams () {
  return {
    destinationAccount: 'some.destination.account.',
    sharedSecretBase64: 'Some+Shared+Secret+in+Base64=='
  }
}

module.exports = {
  getIlpStreamPayParams
}
