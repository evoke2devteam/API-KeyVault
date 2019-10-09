const express = require('express');
const app = express();
const { celebrate, Joi } = require('celebrate');
const bodyParser = require('body-parser');
const KeyVault = require('azure-keyvault');
const AuthenticationContext = require('adal-node').AuthenticationContext;
const credentials = require('./credentials');
const clientId = credentials.clientId;
const clientSecret = credentials.clientSecret;
const vaultUri = credentials.vaultUri;

// Authenticator - retrieves the access token
const authenticator = function (challenge, callback) {
    // Create a new authentication context.
    const context = new AuthenticationContext(challenge.authorization);
    // Use the context to acquire an authentication token.
    return context.acquireTokenWithClientCredentials(challenge.resource, clientId, clientSecret, function (err, tokenResponse) {
        if (err) throw err;
        // Calculate the value to be set in the request's Authorization header and resume the call.
        const authorizationValue = tokenResponse.tokenType + ' ' + tokenResponse.accessToken;
        return callback(null, authorizationValue);
    });
};

// Load the credentials
const credentials = new KeyVault.KeyVaultCredentials(authenticator);
const client = new KeyVault.KeyVaultClient(credentials);

// Parse the request body for check the params
app.use(bodyParser.json());

// API for consult the KeyVault by id
app.get('/show-key-by-id/:id?', celebrate({
    query: Joi.object({
        id: Joi.string().required()
    }).unknown()
}), (err, req, res, next) => {
    res.status(400).send({ status: false, message: 'The id is required' });
}, (req, res) => {
    const secretName = req.query.id;
    const secretVersion = '' //leave this blank to get the latest version;
    client.getSecret(vaultUri, secretName, secretVersion).then((result) => {
        //console.log(result);
        res.status(200).send({ status: true, data: result });
    }).catch((err) => {
        res.status(404).send({ status: false, message: 'Key not found', err: err });
    });
});

// API for create a new KeyVault
app.post('/create-key', celebrate({
    body: Joi.object().keys({
        name: Joi.string().required(),
        value: Joi.string().required(),
    }).unknown()
}), (err, req, res, next) => {
    res.status(400).send({ status: false, message: 'The name and value are required' });
}, (req, res) => {
    const secretName = req.body.name,
        value = req.body.value;
    client.setSecret(vaultUri, secretName, value).then((results) => {
        //console.log(results);
        res.status(200).send({ status: true, result: results });
    }).catch((err) => {
        //console.log(err);
        res.status(400).send({ status: false, message: 'Something went wrong', advice: 'Do not leave spaces between characters' });
    });
});

app.listen(3000, () => {
    console.log("Server Run");
});
