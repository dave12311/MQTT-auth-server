const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const pg = require('pg');
const redis = require('redis');

var app = express();

// Postgres settings
var pool = new pg.Pool({
    user: 'postgres',
    host: 'db',
    database: 'postgres',
    password: 'example',
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
}

app.use(usernameParser);

app.use('/user', auth_user);
app.use('/acl', auth_topic);
app.use('/su', auth_su);

function auth_user(req, res) {
    if(req.mqtt.jwt === true) {
        auth_user_jwt(req, res);
    } else {
        auth_user_http(req, res);
    }
}

function auth_user_http(req, res) {
    const query = 'SELECT password FROM mqtt_auth.http_auth WHERE username = $1';
    pool
    .query(query, [req.body.username])
    .then(result => {
        if(result.rowCount === 1) {
            return bcrypt
            .compare(req.body.password, result.rows[0].password)
            .then(comp => {
                if(comp === true) {
                    console.log('User ' + req.body.username + ' connected using HTTP');
                    res.sendStatus(200);
                } else {
                    console.log('User ' + req.body.username + ' tried to connect with an incorrect password');
                    res.sendStatus(401);
                }
            })
            .catch(err => {
                console.log(err.stack);
                res.sendStatus(500);
            });
        } else {
            console.log('Unregistered user ' + req.body.username + ' tried to connect');
            res.sendStatus(401);
        }
    })
    .catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
}

function auth_user_jwt(req, res) {
    const query = 'SELECT pubkey FROM mqtt_auth.jwt_auth WHERE username = $1';
    pool
   .query(query, [req.mqtt.username])
    .then(result => {
        if(result.rowCount === 1) {
            jwt.verify(req.body.username, result.rows[0].pubkey, function(err, verified) {
                if(err) {
                    console.log('User ' + verified.sub + ' tried to connect using an invalid JWT');
                    res.sendStatus(401);
                } else {
                    console.log('User ' + verified.sub + ' connected using JWT');
                    res.sendStatus(200);
                }
            });
        } else {
            console.log('Unregistered user ' + req.mqtt.username + ' tried to connect using JWT');
            res.sendStatus(401);
        }
    }).catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
}

function auth_topic(req, res) {
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
            } else if((result.rows[0].case & req.body.acc) != 0) {
                console.log('User ' + req.mqtt.username + ' used protected topic ' + req.body.topic + ' (ACC ' + result.rows[0].case.toString(2) + ') with ACC ' + req.body.acc.toString(2));
                res.sendStatus(200);
            } else {
                console.log('User ' + req.mqtt.username + ' tried to use protected topic ' + req.body.topic + ' (ACC ' + result.rows[0].case.toString(2) + ') with ACC ' + req.body.acc.toString(2));
                res.sendStatus(401);
            }
        }
    })
    .catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
}

function auth_su(req, res) {
    const query = 'SELECT EXISTS(SELECT 1 FROM mqtt_auth.su WHERE username = $1)';
    pool
    .query(query, [req.mqtt.username])
    .then(result => {
        if(result.rows[0].exists === true) {
            console.log('User ' + req.mqtt.username + ' used a topic as SU');
            res.sendStatus(200);
        } else {
            res.sendStatus(401);
        }
    })
    .catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
}

app.listen(3000);
console.log("Auth server started.");
