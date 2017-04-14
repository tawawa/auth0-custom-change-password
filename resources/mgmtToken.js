'use strict';

const moment = require('moment');
const request = require('request');
const fs = require('fs');

let accessToken = null;
let lastLogin = null;

function getAuth0AccessToken(config) {

  return new Promise(function (resolve, reject) {
    if (!accessToken || !lastLogin || moment(new Date()).diff(lastLogin, 'minutes') > 30) {
      const options = {
        url: 'https://' + config.AUTH0_DOMAIN + '/oauth/token',
        json: {
          audience: 'https://' + config.AUTH0_DOMAIN + '/api/v2/',
          grant_type: 'client_credentials',
          client_id: config.AUTH0_CLIENT_ID,
          client_secret: config.AUTH0_CLIENT_SECRET
        }
      };

      return request.post(options, function (err, response, body) {
        if (err) {
          return reject(err);
        }
        else {
          lastLogin = moment();
          accessToken = body.access_token;
          console.log(accessToken);
          return resolve(accessToken);
        }
      });
    } else {
      return resolve(accessToken);
    }
  });

};


module.exports = {
  getAuth0AccessToken: getAuth0AccessToken
};
