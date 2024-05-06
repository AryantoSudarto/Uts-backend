const authenticationRepository = require('./authentication-repository');
const { generateToken } = require('../../../utils/session-token');
const { passwordMatched } = require('../../../utils/password');

/**
 * Check username and password for login.
 * @param {string} email - Email
 * @param {string} password - Password
 * @returns {object} An object containing, among others, the JWT token if the email and password are matched. Otherwise returns null.
 */
const LOGIN_ATTEMPT_LIMIT = 5; // Limit percobaan login
const LOGIN_ATTEMPT_TIMEOUT = 30 * 60 * 1000; // Waktu timeout dalam milidetik (30 menit)

let loginAttempts = {}; // Penyimpanan informasi percobaan login

async function updateLoginAttempt(email) {
  if (!loginAttempts[email]) {
    loginAttempts[email] = { attempts: 1, lastAttempt: Date.now() };
  } else {
    loginAttempts[email].attempts++;
    loginAttempts[email].lastAttempt = Date.now();
  }

  // mengecek apakah sudah melebihi limit
  if (loginAttempts[email].attempts >= LOGIN_ATTEMPT_LIMIT) {
    // mengecek apakah sudah melebihi waktu timeout
    if (
      Date.now() - loginAttempts[email].lastAttempt >=
      LOGIN_ATTEMPT_TIMEOUT
    ) {
      // Reset percobaan login jika sudah melebihi batas waktu
      loginAttempts[email].attempts = 1;
      loginAttempts[email].lastAttempt = Date.now();
    } else {
      throw new Error(
        'Too many failed login attempts. Please try again later.'
      );
    }
  }
}

async function checkLoginCredentials(email, password) {
  try {
    // Check login attempts
    await updateLoginAttempt(email);

    const user = await authenticationRepository.getUserByEmail(email);
    const passwordMatched = await passwordMatch(password, user.password);

    // We define default user password here as '<RANDOM_PASSWORD_FILTER>'
    // to handle the case when the user login is invalid. We still want to
    // check the password anyway, so that it prevents the attacker in
    // guessing login credentials by looking at the processing time.
    // const userPassword = user ? user.password : '<RANDOM_PASSWORD_FILLER>';
    // const passwordChecked = await passwordMatched(password, userPassword);

    // Because we always check the password (see above comment), we define the
    // login attempt as successful when the `user` is found (by email) and
    // the password matches.
    if (user && passwordMatched) {
      // Reset login attempts if login is successful
      loginAttempts[email] = { attempts: 1, lastAttempt: Date.now() };

      // Generate and return token
      return {
        email: user.email,
        name: user.name,
        user_id: user.id,
        token: generateToken(user.email, user.id),
      };
    } else {
      throw new Error('Invalid email or password');
    }
  } catch (error) {
    throw error;
  }
}
module.exports = {
  updateLoginAttempt,
  checkLoginCredentials,
};
