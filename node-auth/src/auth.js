const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pg = require('pg');
const redis = require('redis');

var app = express();

var redisClient = redis.createClient({host: 'redis'});
// Redis databases:
// 0: password
// 1: JWT
// 2: SU
// 3: ACL

// Redis cache TTL in seconds
const exp = 20;

// Postgres settings
var pool = new pg.Pool({
    user: process.env.POSTGRES_USER,
    host: 'db',
    database: 'postgres',
    password: process.env.POSTGRES_PASSWORD,
    max: 10,
    idleTimeoutMillis: 30000
});

app.use(bodyParser.json());

var usernameParser = (req, res, next) => {
    var decoded = jwt.decode(req.body.username);
    req.mqtt = {};
    if(decoded) {
        req.mqtt.username = decoded.sub;
        req.mqtt.jwt = true;
    } else {
        req.mqtt.username = req.body.username;
        req.mqtt.jwt = false;
    }

    next();
};

app.use(usernameParser);

app.use('/user', auth_user);
app.use('/acl', auth_topic);
app.use('/su', auth_su);

// User authentication

function auth_user(req, res) {
    if(req.mqtt.jwt === true) {
        auth_user_from_cache(req, res, 1, query_user_jwt, verify_jwt);
    } else {
        auth_user_from_cache(req, res, 0, query_user_http, verify_bcrypt);
    }
};

function auth_user_from_cache(req, res, db, queryFunction, verifyFunction) {
    redisClient.select(db, () => {
        redisClient.get(req.mqtt.username, (err, reply) => {
            if(err) {
                console.log('Credential cache error');
                console.log(err.stack);
                queryFunction(req, res, null);
            } else if(reply) {
                console.log('Used cached credentials');
                verifyFunction(req, res, JSON.parse(reply));
            } else {
                console.log('No cached credentials');
                queryFunction(req, res, null);
            }
        });
    });
};

async function verify_bcrypt(req, res, data) {
    var dateNow = new Date();
    if((data.expiry == null || Date.parse(data.expiry) >= dateNow) && data.credits > 0) {
        return bcrypt
        .compare(req.body.password, data.password)
        .then(comp => {
            if(comp === true) {
                console.log('User ' + req.body.username + ' connected using HTTP');
                res.sendStatus(200);
            } else {
                console.log('User ' + req.body.username + ' tried to connect with an incorrect password');
                res.sendStatus(401);
            }
            redisClient.set(req.body.username, JSON.stringify(data), 'EX', exp);
        })
        .catch(err => {
            console.log(err.stack);
            res.sendStatus(500);
        });
    } else {
        console.log('User ' + req.mqtt.username + ' has an expired account or no credits');
        res.sendStatus(401);
    }
};

function verify_jwt(req, res, data) {
    var dateNow = new Date();
    if((data.expiry == null || Date.parse(data.expiry) >= dateNow) && data.credits > 0) {
        jwt.verify(req.body.username, data.pubkey, (err, verified) => {
            if(err) {
                console.log('User ' + req.mqtt.username + ' tried to connect using an invalid JWT');
                res.sendStatus(401);
            } else if(verified){
                console.log('User ' + req.mqtt.username + ' connected using JWT');
                res.sendStatus(200);
            } else {
                res.sendStatus(500);
            }
            redisClient.set(req.mqtt.username, JSON.stringify(data), 'EX', exp);
        });
    } else {
        console.log('User ' + req.mqtt.username + ' has an expired account or no credits');
        res.sendStatus(401);
    }
};

async function query_user_http(req, res) {
    const query = 'SELECT password, credits, expiry FROM mqtt_auth.http_auth WHERE username = $1';
    return pool
    .query(query, [req.body.username])
    .then(result => {
        if(result.rowCount >= 1) {
            verify_bcrypt(req, res, result.rows[0]);
        } else {
            console.log('Unregistered user ' + req.body.username + ' tried to connect');
            res.sendStatus(401);
        }
    })
    .catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
};

async function query_user_jwt(req, res) {
    const query = 'SELECT pubkey, credits, expiry FROM mqtt_auth.jwt_auth WHERE username = $1';
    return pool
    .query(query, [req.mqtt.username])
    .then(result => {
        if(result.rowCount >= 1) {
            verify_jwt(req, res, result.rows[0]);
        } else {
            console.log('Unregistered user ' + req.mqtt.username + ' tried to connect using JWT');
            res.sendStatus(401);
        }
    }).catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
};

// ACL verification

function auth_topic(req, res) {
    redisClient.select(3, () => {
        redisClient.get(req.mqtt.username + req.body.topic, (err, reply) => {
            if(err) {
                console.log('ACL cache error');
                console.log(err.stack);
                query_topic(req, res);
            } else if(reply) {
                console.log('Used cached ACL');
                if((reply & req.body.acc) != 0) {
                    console.log('User ' + req.mqtt.username + ' used protected topic ' + req.body.topic + ' (ACC ' + reply.toString(2) + ') with ACC ' + req.body.acc.toString(2));
                    res.sendStatus(200);
                } else {
                    console.log('User ' + req.mqtt.username + ' tried to use protected topic ' + req.body.topic + ' (ACC ' + reply.toString(2) + ') with ACC ' + req.body.acc.toString(2));
                    res.sendStatus(401);
                }
            } else {
                console.log('No cached ACL');
                query_topic(req, res);
            }
        });
    });
};

async function query_topic(req, res) {
    const query = 'SELECT CASE WHEN username = $1 THEN acc END FROM mqtt_auth.acl WHERE topic = $2';
    pool
    .query(query, [req.mqtt.username, req.body.topic])
    .then(result => {
        if(result.rowCount === 0) {
            console.log('User ' + req.mqtt.username + ' used unprotected topic ' + req.body.topic);
            res.sendStatus(200);
        } else {
            if(result.rows[0].case == null) {
                console.log('User ' + req.mqtt.username + ' tried to use protected topic ' + req.body.topic);
                res.sendStatus(401);
                redisClient.set(req.mqtt.username + req.body.topic, 0, 'EX', exp);
            } else if((result.rows[0].case & req.body.acc) != 0) {
                console.log('User ' + req.mqtt.username + ' used protected topic ' + req.body.topic + ' (ACC ' + result.rows[0].case.toString(2) + ') with ACC ' + req.body.acc.toString(2));
                res.sendStatus(200);
                redisClient.set(req.mqtt.username + req.body.topic, result.rows[0].case, 'EX', exp);
            } else {
                console.log('User ' + req.mqtt.username + ' tried to use protected topic ' + req.body.topic + ' (ACC ' + result.rows[0].case.toString(2) + ') with ACC ' + req.body.acc.toString(2));
                res.sendStatus(401);
                redisClient.set(req.mqtt.username + req.body.topic, result.rows[0].case, 'EX', exp);
            }
        }
    })
    .catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
};

// Superuser authentication

function auth_su(req, res) {
    redisClient.select(2, () => {
        redisClient.get(req.mqtt.username, (err, reply) => {
            if(err) {
                console.log('SU cache error');
                console.log(err.stack);
                query_su(req, res);
            } else if(reply) {
                console.log('Used cached SU');
                if(reply === 'true') {
                    console.log('User ' + req.mqtt.username + ' used a topic as SU');
                    res.sendStatus(200);
                } else {
                    res.sendStatus(401);
                }
            } else {
                console.log('No cached SU');
                query_su(req, res);
            }
        });
    });
};

async function query_su(req, res) {
    const query = 'SELECT EXISTS(SELECT 1 FROM mqtt_auth.su WHERE username = $1)';
    return pool
    .query(query, [req.mqtt.username])
    .then(result => {
        if(result.rows[0].exists === true) {
            console.log('User ' + req.mqtt.username + ' used a topic as SU');
            res.sendStatus(200);
            redisClient.set(req.mqtt.username, true, 'EX', exp);
        } else {
            res.sendStatus(401);
            redisClient.set(req.mqtt.username, false, 'EX', exp);
        }
    })
    .catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
};

app.listen(3000);
console.log("Auth server started.");
