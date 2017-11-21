import jwt from 'jsonwebtoken';
import moment from 'moment';

/**
 * GET /lock/:_id
 * Attempts to acquire a lock for the file
 */
const lockFile = (req, res) => {
  let lockedFiles = req.app.get('lockedFiles');

  // TODO: Add Auth as header
  const { _id } = req.params;
  const { email } = req.query;

  //TODO Verify email with Directory Service?
  if(!_id || !email) {
    return res.status(403).send({granted: false, message: `Invalid fields - email: ${email}, _id: ${_id}`});
  }
  const { secret, expiry } = req.app.get('jwt');
  const lock = lockedFiles.get(_id);
  if(!lock || lock.expiresAt.isBefore(moment()) ||lock.email === email) {
    // Give Lock
    const lock = jwt.sign({data: {email, _id}}, secret, {expiresIn: `${expiry}m`});
    lockedFiles.set(_id, {email, expiresAt: moment().add(expiry, 'm')});
    res.send({granted: true, message: `Lock expires in ${expiry}m`, lock});
    console.log(lockedFiles);
  } else {
    res.send({granted: false, message: `Lock is in use - try again later`});
  }
};

/**
 * PUT unlock/:id
 * Unlocks a file (if lock was previously given to <email> for file <_id>
 */
const unlockFile = (req, res) => {
  const { lock, email, _id } = req.body;
};


/**
 * POST /validate
 * Checks if a token is valid (requested by File System Nodes)
 */
const validateLock = (req, res) => {
  const { lock, email, _id } = req.body;
  res.send(isLockValid(lock, email, _id, req.app.get('jwt')));
};


/**
 * Helper function to check if lock is valid
 * @param lock the JWT
 * @param email the user who apparently received the lock
 * @param _id the _id of the apparent file they locked
 * @param jwtParams jwtSecret and expiry
 * @returns {valid: boolean, message: String}
 */
function isLockValid(lock, email, _id, jwtParams) {
  const { secret } = jwtParams;
  try {
    let decoded = jwt.verify(lock, secret);
    const { exp, data } = decoded;


    if(data._id !== _id) {
      return {
        valid: false,
        message: `Token not issued for file ${_id}`
      }
    } else if(data.email !== email) {
      return {
        valid: false,
        message: `Token not issued to ${email}`
      }
    }

    return {
      valid: true,
      message: `Token Valid until ${new Date(exp*1000)}`
    }

  } catch(err) {
    return {
      valid: false,
      message: err.message
    }
  }

}

module.exports = {
  lockFile,
  unlockFile,
  validateLock
};


