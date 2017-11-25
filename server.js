import crypto from 'crypto';
import express from 'express';
import moment from 'moment';
import bodyParser from 'body-parser';
import morgan from 'morgan';

// Import Controllers
import LockingController from './controllers/LockingController';

// Initialize .env
require('dotenv').config();

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


// TODO: Add mongodb support
// import mongoose from 'mongoose';
// Initialize the DB
// const dbURL = "mongodb://localhost/dfs_filesystem";
// mongoose.connect(dbURL);
// const db = mongoose.connection;
// db.on('error', console.error.bind(console, 'connection error:'));
// db.once('open', function() {
//   console.log("Connected to Database");
// });




let lockedFiles = new Map();
app.set('lockedFiles', lockedFiles);

// expose environment variables to app
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
      console.log(`Token expired on ${expires.format()}`);
      return res.status(401).send({message: `Authorization token expired on ${expires.format()}`});
    }

    // Pass the controllers the decrypted body and the client's _id
    req.clientId = _id;
    if(req.body.encrypted) {
      req.decrypted =  decrypt(req.body.encrypted, sessionKey);
    }
  }

  // If JSON couldn't be parsed, the token was
  catch(err) {
    console.error(err);
    return res.status(401).send({message: `Invalid authorization key provided`})
  }

  next()
};

app.use(authenticator);


// Endpoints
app.get('/lock/:_id', LockingController.lockFile);
app.put('/unlock/:_id', LockingController.unlockFile);
app.post('/validate', LockingController.validateLock);


// Initialize the Server
app.listen(3002, function() {
  console.log('Locking Server on port 3002');
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
