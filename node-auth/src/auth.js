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

// HTTP
app.use('/http', bodyParser.json());

app.use('/http/user', auth_user_http);
app.use('/http/acl', auth_topic);
app.use('/http/su', auth_su_http);

// JWT
app.use('/jwt/user', auth_user_jwt);
app.use('/jwt/acl', bodyParser.json());
app.use('/jwt/acl', auth_topic);
//app.use('/jwt/su', debug);

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
                    console.log('User ' + req.body.username + ' logged in');
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
            console.log('Unregistered user ' + req.body.username + ' tried to log in');
            res.sendStatus(401);
        }
    })
    .catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
}

function auth_user_jwt(req, res) {
    var decoded_jwt = jwt.decode(req.headers.authorization);
    if(decoded_jwt != null) {
        const query = 'SELECT pubkey FROM mqtt_auth.jwt_auth WHERE username = $1';
        pool
        .query(query, [decoded_jwt.sub])
        .then(result => {
            if(result.rowCount === 1) {
                jwt.verify(req.headers.authorization, result.rows[0].pubkey, function(err, decoded) {
                    console.log(decoded);
                    if(err) {
                        console.log('Invalid JWT for ' + decoded_jwt.sub);
                        res.sendStatus(401);
                    } else {
                        console.log(decoded.sub + ' connected using JWT');
                        res.sendStatus(200);
                    }
                });
            } else {
                res.sendStatus(401);
            }
        }).catch(err => {
            console.log(err.stack);
            res.sendStatus(500);
        });
    } else {
        console.log('Incorrect JWT token');
        res.sendStatus(400);
    }
}

function auth_topic(req, res) {
    const query = 'SELECT EXISTS(SELECT 1 FROM mqtt_auth.acl WHERE topic = $1)';
    console.log(req.body);
    console.log(req.body.username);
    console.log(req.headers.authorization);
    var uname;
    var decoded = jwt.decode(req.headers.authorization);
    if(decoded) {
        uname = decoded.sub;
    } else {
        uname = req.body.username;
    }
    console.log('UNAME');
    console.log(uname);
    pool
    .query(query, [req.body.topic])
    .then(result => {
        if(result.rows[0].exists === true) {
            const subquery = 'SELECT acc FROM mqtt_auth.acl WHERE topic = $1 AND username = $2';
            return pool
            .query(subquery, [req.body.topic, uname])
            .then(subresult => {
                if((subresult.rows[0].acc & req.body.acc) != 0) {
                    console.log('User ' + uname + ' used protected topic ' + req.body.topic + ' (ACC ' + subresult.rows[0].acc.toString(2) + ') with ACC ' + req.body.acc.toString(2));
                    res.sendStatus(200);
                } else {
                    console.log('User ' + uname + ' tried to use protected topic ' + req.body.topic + ' (ACC ' + subresult.rows[0].acc.toString(2) + ') with ACC ' + req.body.acc.toString(2));
                    res.sendStatus(401);
                }
            })
            .catch(suberr => {
                console.log(suberr.stack);
                res.sendStatus(500);
            });
        } else {
            console.log('User ' + uname + ' used unprotected topic ' + req.body.topic);
            res.sendStatus(200);
        }
    })
    .catch(err => {
        console.log(err.stack);
        res.sendStatus(500);
    });
}

function auth_su_http(req, res) {
    const query = 'SELECT EXISTS(SELECT 1 FROM mqtt_auth.su WHERE username = $1)';
    pool
    .query(query, [req.body.username])
    .then(result => {
        if(result.rows[0].exists === true) {
            console.log('User ' + req.body.username + ' promoted to SU');
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

function auth_su_jwt(req, res) {

}

app.listen(3000);
console.log("Auth server started.");
