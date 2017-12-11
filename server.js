import crypto from 'crypto';
import express from 'express';
import moment from 'moment';
import bodyParser from 'body-parser';
import morgan from 'morgan';
import dotenv from 'dotenv';
dotenv.config();

// Import Controllers
import * as LockingController from './controllers/LockingController';

// Make encryption parameters accessible
const encryption = {
  algorithm: process.env.SYMMETRIC_ENCRYPTION,
  plainEncoding: process.env.PLAIN_ENCODING,
  encryptedEncoding: process.env.ENCRYPTED_ENCODING,
  serverKey: process.env.SERVER_KEY
};


// Create the server
const app = express();
app.use(bodyParser.urlencoded({extended: true}));   // Parses application/x-www-form-urlencoded for req.body
app.use(bodyParser.json());                         // Parses application/json for req.body
app.use(morgan('dev'));

// Expost lockedFiles Map to controllers
let lockedFiles = new Map();
app.set('lockedFiles', lockedFiles);

// Expose JSON Web Token params to controllers
app.set('jwt', {secret: process.env.JWT_SECRET, expiry: process.env.JWT_EXPIRY});


// Middleware to authenticate / decrypt incoming requests
const authenticator = (req, res, next) => {

  // Ensure auth ticket exists
  const { authorization } = req.headers;
  if(!authorization) {
    return res.status(401).send({message: `No authorization key provided`});
  }

  try {
    // Decrypt auth ticket with server's private key
    const ticket = decrypt(authorization);

    // Parse the ticket from the decrypted string
    let { _id, expires, sessionKey } = JSON.parse(ticket);
    expires = moment(expires);


    // Ensure the ticket is in date
    if(moment().isAfter(expires)) {
      console.log(`Ticket expired on ${expires.format()}`);
      return res.status(401).send({message: `Authorization token expired on ${expires.format()}`});
    }

    // Pass the controllers the decrypted body and the client's _id
    req.clientId = _id;
    if(req.body.encrypted) {
      req.decrypted = JSON.parse(decrypt(req.body.encrypted, sessionKey));
    }
  }

  // If JSON couldn't be parsed, the token was invalid
  catch(err) {
    console.error(err);
    return res.status(401).send({message: `Invalid authorization key provided`})
  }

  next()
};


// Inter Service communication endpoint
app.post('/validate', LockingController.validateLock);

app.use(authenticator);

// Authenticated Endpoints
app.get('/lock/:_id', LockingController.lockFile);
app.put('/unlock/:_id', LockingController.unlockFile);


const port = process.argv[2] || process.env.PORT || 3002;

// Initialize the Server
app.listen(port, function() {
  console.log(`Locking Server on port ${port}`);
});


/**
 * Decrypts the data using parameters defined in .env file
 * @param data to be decrypted
 * @param key used during the encryption
 */
function decrypt(data, key=encryption.serverKey) {
  const { algorithm, plainEncoding, encryptedEncoding } = encryption;

  const decipher = crypto.createDecipher(algorithm, key);
  let deciphered = decipher.update(data, encryptedEncoding, plainEncoding);
  deciphered += decipher.final(plainEncoding);

  return deciphered
}
