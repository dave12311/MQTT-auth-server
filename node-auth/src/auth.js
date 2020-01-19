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

app.use('/http', bodyParser.json());

// HTTP
app.use('/http/user', auth_user);
app.use('/http/acl', auth_topic);
app.use('/http/su', auth_su);

// JWT
app.use('/jwt', (req, res) => {
    res.sendStatus(401);
});

function auth_user(req, res) {
    const query = 'SELECT password from mqtt_auth.http_auth WHERE username = $1';
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

function auth_topic(req, res) {
    const query = 'SELECT EXISTS(SELECT 1 FROM mqtt_auth.acl WHERE topic = $1)';
    pool
    .query(query, [req.body.topic])
    .then(result => {
        if(result.rows[0].exists === true) {
            const subquery = 'SELECT acc FROM mqtt_auth.acl WHERE topic = $1 AND username = $2';
            return pool
            .query(subquery, [req.body.topic, req.body.username])
            .then(subresult => {
                if(subresult.rowCount > 0 && (subresult.rows[0].acc & req.body.acc) != 0) {
                    console.log('User ' + req.body.username + ' connected to protected topic ' + req.body.topic + ' with ACC ' + req.body.acc);
                    res.sendStatus(200);
                } else {
                    console.log('User ' + req.body.username + ' tried to connect to protected topic ' + req.body.topic + ' with ACC ' + req.body.acc);
                    res.sendStatus(401);
                }
            })
            .catch(suberr => {
                console.log(suberr.stack);
                res.sendStatus(500);
            });
        } else {
            console.log('User ' + req.body.username + ' connected to unprotected topic ' + req.body.topic);
            res.sendStatus(200);
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

app.listen(3000);
console.log("Auth server started.");