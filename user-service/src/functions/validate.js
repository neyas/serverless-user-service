"use strict";
const jwt = require("jsonwebtoken");
module.exports.validate = async (event, context) => {
  const authorizationToken = event.authorizationToken;
  const authArr = authorizationToken.split(" ");
  const token = authArr[1];
  if (
    authArr.length !== 2 ||
    authArr[0] !== "Bearer" ||
    authArr[1].length === 0
  ) {
    return generatePolicy('undefined', 'Deny', event.methodArn);
  }
  let decodedJwt = jwt.verify(token, 'mysecret');
  if (
    typeof decodedJwt.username !== 'undefined' &&
    decodedJwt.username.length > 0
  ) {
    // you can do database lookup
    return generatePolicy(decodedJwt.username, 'Allow', event.methodArn);
  } else {
    return generatePolicy('undefined', 'Deny', event.methodArn);
  }
};

// Help function to generate an IAM policy
const generatePolicy = function (principalId, effect, resource) {
  let authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {
    let policyDocument = {};
    policyDocument.Version = "2012-10-17";
    policyDocument.Statement = [];
    let statementOne = {};
    statementOne.Action = "execute-api:Invoke";
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  return authResponse;
};
