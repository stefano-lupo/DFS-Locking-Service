# Distributed File System: Locking Service
This repo contains the code for the Locking Service for my distributed file system. Links to all components of my file system can be found in the repo for the [test client and client library](https://github.com/stefano-lupo/DFS-Client)

## Encryption / Authentication
All client requests are behind a piece of middleware which examines the supplied token, attempts to decrypt it using the server key (known to all server nodes) and verify its contents. This middleware also sets the `clientId` (contained in the encrypted token) field of an incoming request (if it could be authenticated), allowing the controllers to know which client they are servicing. Finally, it also sets `req.decrypted` with the decrypted contents of the body of any POST requests.

# The Locking Service
### JSON Web Tokens
The heart of the Locking Services are JSON Web Tokens. JWT are the data that is used to represent a lock and consist of the following:
- `clientId`: the `_id` of the client who this lock is for
- `_id`: the `_id` of the file this lock is for
- `expiry`: a timestamp indicating when this lock will expire.

This data structure is then encrypted using a secret key known only to the locking server. Locks are enforced by the master file system node on any attempts to write to a file. The master node will make a call to the locking service in order to validate the lock. 

### Validating Locks
There are four checks to be peformed when validating the lock:
1. The lock is decryptable (using the Locking Service's secret key).
2. The lock has not yet expired.
3. The lock was given to the client who is currently trying to update the file (not just that *someone* has locked the file).
4. The lock is for the file that the client is currently trying to write to (not just that the client has a lock for *any* file).

If any of these four checks fail, the write operation is rejected. 

The first two of these checks are handled during the decryption using the `jwt.verify(lock, secret)` call to the [JWT package](https://github.com/auth0/node-jsonwebtoken) which throws an exception if the token is invalid or out of date. Provided both these tests pass, we now have access to the data that the token initially encrypted: the `clientId` and `_id` of the file. Thus these can both be checked against the `_id` of the client making the write request and the `_id` of the file they are trying to write to.

### Granting / Denying Lock Requests
The Locking Service maintains a `lockedFiles` Map which maps from file `_id` --> `{clientId, expiresAt}`. Upon receiving a request for a lock on a file, the Locking Service checks the following:

1. If there is no entry in the `lockedFiles` map for this file `_id`
2. If there is an entry, but the lock has expired
3. If the lock was given to the same client that is currently requesting it

In any of these three cases the lock is given as:
1. The file is not locked
2. The file **was** locked but the lock has expired.
3. The client is extending a lock it already has.


## Client API
#### `GET /lock/:_id`
- Attempts to lock file `_id` for client `clientId` (contained in the Auth token).
- Returns a `granted` boolean indicating whether or not the lock was given and the JWT that represents the lock if it was.

#### `PUT /unlock/:_id`
- **body**
  - `lock`: the JWT that represents the lock to be released.
- This is to be used by Client's when they have finished writing to a file.
- The `lock` is required so it can be validated as described above to ensure the releasing of a lock cannot be spoofed by other clients on behalf of the lock holder.



## Inter Service API
#### `POST /validate`
- **body**
  - `clientId`: the `_id` of the client who is making the write request
  - `lock`: the `lock` they provided for the write request
  - `_id`: the `_id` of the file they wish to write to
- This endpoint is used by the master server in order to ensure a lock is legitimate and that it may proceed with the write operation.



