import jwt from 'jsonwebtoken';

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
  if(!lockedFiles.get(_id) || lockedFiles.get(_id) === email) {
    // Give Lock
    const lock = jwt.sign({data: {email, _id}}, secret, {expiresIn: `${expiry}m`});
    lockedFiles.set(_id, email);
    res.send({granted: true, message: `Lock expires in ${expiry}m`, lock});
    console.log(lockedFiles);
  } else {
    res.send({granted: false, message: `Lock is in use - try again later`});
  }
};


const unlockFile = (req, res) => {

};

const validateLock = (req, res) => {
  const { lock, email, _id } = req.body;
  res.send(isLockValid(lock, email, _id, req.app.get('jwt')));
};

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


