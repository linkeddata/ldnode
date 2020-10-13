/* global location, alert, solid */
/* Provide functionality for authentication buttons */

((SessionManager) => {
  // Wire up DOM elements
  const [
    loginButton,
    logoutButton,
    registerButton,
    accountSettings,
    loggedInContainer,
    profileLink
  ] = [
    'login',
    'logout',
    'register',
    'account-settings',
    'loggedIn',
    'profileLink'
  ].map(id => document.getElementById(id) || document.createElement('a'))
  loginButton.addEventListener('click', login)
  logoutButton.addEventListener('click', logout)
  registerButton.addEventListener('click', register)

  function onSessionChange(sessionInfo) {
    const loggedIn = sessionInfo.isLoggedIn
    const isOwner = loggedIn && new URL(sessionInfo.webId).origin === location.origin
    loginButton.classList.toggle('hidden', loggedIn)
    logoutButton.classList.toggle('hidden', !loggedIn)
    registerButton.classList.toggle('hidden', loggedIn)
    accountSettings.classList.toggle('hidden', !isOwner)
    loggedInContainer.classList.toggle('hidden', !loggedIn)
    if (sessionInfo) {
      profileLink.href = sessionInfo.webId
      profileLink.innerText = sessionInfo.webId
    }
  }

  const session = new SessionManager.Session(
    {
      clientAuthentication: solidClientAuthentication.getClientAuthenticationWithDependencies(
        {}
      ),
    },
    "mySession"
  );

  const authCode = new URL(window.location.href).searchParams.get("code")
  if (authCode) {
    // Being redirected after requesting a token
    session
      .handleIncomingRedirect(new URL(window.location.href))
      .then((sessionInfo) => {
        onSessionChange(sessionInfo)
      });
  } else {
    onSessionChange(session.info)
  }

  // Log the user in on the client and the server
  async function login () {
    // TODO: This should be made to look nicer.
    const thisUrl = new URL(window.location.href).origin
    const issuer = prompt("Enter an issuer", thisUrl)
    session.login({
      redirectUrl: new URL(window.location.href),
      oidcIssuer: new URL(issuer),
    });
  }

  // Log the user out from the client and the server
  async function logout () {
    await session.logout()
    location.reload()
  }

  // Redirect to the registration page
  function register () {
    const registration = new URL('/register', location)
    location.href = registration
  }
})(solidClientAuthentication)
