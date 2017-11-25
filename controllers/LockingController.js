import jwt from 'jsonwebtoken';
import moment from 'moment';

/**
 * GET /lock/:_id
 * Attempts to acquire a lock for the file
 */
const lockFile = (req, res) => {

  const { _id } = req.params;
  const { clientId } = req;

  if(!_id) {
    return res.status(409).send({granted: false, message: `No file _id requested for lock`});
  }

  let lockedFiles = req.app.get('lockedFiles');
  const { secret, expiry } = req.app.get('jwt');

  const lock = lockedFiles.get(_id);
  if(!lock || lock.expiresAt.isBefore(moment()) || lock.clientId === clientId) {
    // File is not locked, lock expired or lock already belongs to client (extend)
    const lock = jwt.sign({data: {clientId, _id}}, secret, {expiresIn: `${expiry}m`});
    lockedFiles.set(_id, {clientId, expiresAt: moment().add(expiry, 'm')});
    res.send({granted: true, message: `Lock expires in ${expiry}m`, lock});
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
 * body: {lock, email, _id}
 * Checks if a token is valid (requested by File System Nodes)
 */
const validateLock = (req, res) => {
  const { clientId } = req;
  const { lock, _id } = req.body;
  if(!lock) {
    return res.status(409).send({
      valid: false,
      message: `No Lock provided`
    });
  }
  res.send(isLockValid(lock, _id, clientId, req.app.get('jwt')));
};


/**
 * Helper function to check if lock is valid
 * @param lock the JWT
 * @param clientId the user who apparently received the lock
 * @param _id the _id of the apparent file they locked
 * @param jwtParams jwtSecret and expiry
 * @returns {valid: boolean, message: String}
 */
function isLockValid(lock, _id, clientId, jwtParams) {
  const { secret } = jwtParams;
  try {
    let decoded = jwt.verify(lock, secret);
    const { exp, data } = decoded;

    // Check the lock was actually acquired for this file
    if(data._id !== _id) {
      return {
        valid: false,
        message: `Token not issued for file ${_id}`
      }
    }

    // Check the lock was actually acquired by this client
    else if(data.clientId !== clientId) {
      return {
        valid: false,
        message: `Token not issued to ${clientId}`
      }
    }

    return {
      valid: true,
      message: `Token Valid until ${new Date(exp*1000)}`
    }

  } catch(err) {
    // Lock couldn't be verified
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


