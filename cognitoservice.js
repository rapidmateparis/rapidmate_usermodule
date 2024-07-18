const crypto = require('crypto');

const bcrypt = require('bcryptjs');

//const audit = require('./audit'),

const { CognitoJwtVerifier } = require("aws-jwt-verify");

var AWS = require("aws-sdk");
var AmazonCognitoIdentity = require("amazon-cognito-identity-js");
var cognito_poolId = '';
var cognito_region = '';
var cognito_accessKeyId = '';
var cognito_secretAccessKey = '';
const userPoolId = '';
const ClientId = '';

const DELEIVERY_BOY_ROLE = "deliveryboy";

const logger = require('log4js').getLogger(require('path').basename(__filename));

var poolData =
{
    UserPoolId : userPoolId, // Your user pool id here
    ClientId :  ClientId// sempercon2 client id here
};


const jwtVerifier = CognitoJwtVerifier.create({
    userPoolId: userPoolId,
    tokenUse: "access",
    clientId: ClientId,
    Scope: "read",
    includeRawJwtInErrors: true
});


function createUser(userInfo) {
  return new Promise(resolve => {

        logger.info("createUser called");

        var UserAttributes = [
            {
                Name: 'name', Value: userInfo["userName"]
            },
            {
                Name: 'email', Value: userInfo["userName"]
            },
            {
                Name: 'phone_number', Value: userInfo["phoneNumber"]
            },
            {
                Name: 'custom:userrole', Value: userInfo["userrole"]
            }
        ]


        var params =
        {
            UserPoolId: userPoolId, // Your user pool id here
            Username: userInfo["userName"],
            DesiredDeliveryMediums:
            [ "EMAIL"],
            //TemporaryPassword: 'Password_1',
            UserAttributes: UserAttributes
        };

        var cognitoidentityserviceprovider  = new AWS.CognitoIdentityServiceProvider({region:cognito_region,
          accessKeyId: cognito_accessKeyId,
          secretAccessKey: cognito_secretAccessKey,
          poolId: cognito_poolId});

        cognitoidentityserviceprovider.adminCreateUser(params,function(err, data)
        {
            if (err) {
                logger.error('createUser error')
                logger.error(err);
                resolve(err);
            }
            else {
                logger.info(data);
                logger.info("createUser completion");
                delete params["UserAttributes"];
                delete params["DesiredDeliveryMediums"];
                resolve(updateandSendUserInfo(cognitoidentityserviceprovider, params));
            }
        });
  });
}

function signup(userInfo) {
  return new Promise((resolve, reject) => {
    logger.info("selfSignUp called");

    const UserAttributes = [
       // this field only in consumer
      {
        Name: 'name',
        Value: userInfo["userName"]
      },
      // end 
      {
        Name: 'email',
        Value: userInfo["userName"]
      },
      {
        Name: 'phone_number',
        Value: userInfo["phoneNumber"]
      },
      //enterprise
      {
        Name:'first_name',
        Value:userInfo["firstName"]
      },
      {
        Name:"last_name",
        Value:userInfo["lastName"]
      },
      {
        Name:"company_name",
        Value:userInfo["companyName"]
      },
      {
        Name:"industry",
        Value:userInfo["industry"]
      },
      {
        Name:"delivery_per_hour",
        Value:userInfo["deliveryPerHour"]
      },
      {
        Name:"description",
        Value:userInfo["description"]
      },
      {
        Name:"term_cond2",
        Value:userInfo["termCondtwo"]
      },

      // end enterprise
      
      
      // consumer signup field
      {
        Name:"account_type",
        Value:userInfo["accountType"]
      },
      // end consumer

      // this field add in delivery boy  and enterprise
      {
        Name:"term_cond1",
        Value:userInfo["termCondone"]
      },
      {
        Name:"city",
        Value:userInfo["city"]
      },
      {
        Name:"state",
        Value:userInfo["state"]
      },
      {
        Name:"country", //you can add "country_id"
        Value:userInfo["country"]
      },
      {
        Name:"siret_no",
        Value:userInfo["siretNo"]
      }
      
      // end 

      /*,
      {
        Name: 'custom:userrole',
        Value: userInfo["userrole"]
      }*/
    ];

    const params = {
      ClientId: ClientId, // Your app client id here
      Username: userInfo["userName"],
      Password: userInfo["password"], // Collect user password for self-signup
      UserAttributes: UserAttributes
    };

    const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({
      region: cognito_region,
      accessKeyId: cognito_accessKeyId,
      secretAccessKey: cognito_secretAccessKey
    });

    cognitoidentityserviceprovider.signUp(params, function(err, data) {
      if (err) {
        logger.error('selfSignUp error');
        logger.error(err);
        reject(err);
      } else {
        logger.info(data);
        logger.info("selfSignUp completion");
        resolve(data);
      }
    });
  });
}

function signupVerify(userInfo) {
  return new Promise((resolve, reject) => {
    logger.info("selfSignUp called");



    const params = {
      ClientId: ClientId, // Your app client id here
      Username: userInfo["userName"],
      ConfirmationCode: userInfo["code"], // Collect user password for self-signup
    };

    const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({
      region: cognito_region,
      accessKeyId: cognito_accessKeyId,
      secretAccessKey: cognito_secretAccessKey
    });

    cognitoidentityserviceprovider.confirmSignUp(params, function(err, data) {
      if (err) {
        logger.error('selfSignUp error');
        logger.error(err);
        reject(err);
      } else {
        logger.info(data);
        logger.info("selfSignUp completion");
        resolve(data);
      }
    });
  });

}


function login(userInfo) {
  return new Promise((resolve , reject) => {

            var authenticationData =
            {
                Username : userInfo["userName"],
                Password : userInfo["password"],
            };
            var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
            var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

            var userData =
            {
                Username : userInfo["userName"],
                Pool : userPool
            };
            var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

            cognitoUser.authenticateUser(authenticationDetails,
            {
                newPasswordRequired: function (userAttributes, requiredAttributes)
                {
                    var newPassword = userInfo["newPassword"];
                    if(newPassword) {

                      /*delete userAttributes['email_verified'];
                      delete userAttributes['phone_number'];
                      delete userAttributes['email'];*/

                      var nUserAttributes = {};
                      nUserAttributes["name"] = userAttributes["name"];
                      var successDelegate = this;

                      cognitoUser.completeNewPasswordChallenge(newPassword, nUserAttributes,
                      {
                          onSuccess: function (result)
                          {
                              logger.info("onSuccess");
                              logger.info(result);
                              //resolve(setandSendUserInfo(cognitoUser, result));
                              resolve(updateEmailVerification(cognitoUser, result, userInfo["userName"]));
                          },
                          onFailure: function(cognitoErr)
                          {
                              logger.error("completeNewPasswordChallenge onFailure");
                              logger.error(cognitoErr);
                              resolve(cognitoErr);
                          },
                      });

                    } else {
                      var body = {};
                      body["error"] = {"message" : "newPasswordRequired"};
                      body["userAttributes"] = userAttributes;
                      body["requiredAttributes"] = requiredAttributes;
                      resolve(body);
                    }
                },
                onSuccess: function (result)
                {
                    logger.info("onSuccess");
                    logger.info(result);
                    //resolve(setandSendUserInfo(cognitoUser, result));
                    resolve(result);
                },
                onFailure: function(cognitoErr)
                {
                    logger.error("onFailure");
                    logger.error(cognitoErr);
                    resolve(cognitoErr);
                },
            });
      });
}

function setandSendUserInfo(cognitoUser, sessionInfo) {

    return new Promise(resolve => {

        cognitoUser.getUserAttributes( function(err, userAttributes)
        {
            if (err) {
                logger.error("setandSendUserInfo");
                resolve(err);
            }
            else {
              logger.info("userAttributes ********");
              logger.info(userAttributes);
              linkCognitoUserWithLocalDatabase(userAttributes, true).then(userLocalInfo => {
                 logger.info(userLocalInfo);

                 var responseDict = {};
                 responseDict["userInfo"] = userLocalInfo;
                 responseDict["sessionInfo"] = sessionInfo;
                 resolve(responseDict);
              });
            }
        });

    });

}

function updateEmailVerification(cognitoUser, sessionInfo, loginUserName) {
    return new Promise((resolve, reject) => {

        logger.info("update email verification");
        logger.info("loginUserName:" + loginUserName);
        var UserAttributes = [];

        UserAttributes[UserAttributes.length] = { Name: 'email_verified', Value: "true" };
        logger.info(UserAttributes);

        var params = {
            UserPoolId: userPoolId, // Your user pool id here
            Username: loginUserName,
            UserAttributes: UserAttributes
        };

        var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({
            region: cognito_region,
            accessKeyId: cognito_accessKeyId,
            secretAccessKey: cognito_secretAccessKey,
            poolId: cognito_poolId
        });

        cognitoidentityserviceprovider.adminUpdateUserAttributes(params, function (err, data) {
            if (err) {
                logger.error("updateEmailVerification");
                logger.error(err);
                resolve(err);
            }
            else {
                logger.info(data);
                delete params["UserAttributes"];
                resolve(setandSendUserInfo(cognitoUser, sessionInfo));
            }
        });
    });
}

function updateAttributes(userInfo) {
  return new Promise((resolve , reject) => {

          var UserAttributes = [];
          var username = userInfo["userName"];


          if(userInfo["phoneNumber"]) {
              UserAttributes[UserAttributes.length] = { Name: 'phone_number', Value: userInfo["phoneNumber"] };
          }

          if(userInfo["userrole"]) {
              UserAttributes[UserAttributes.length] = { Name: 'custom:userrole', Value: userInfo["userrole"] };
          }

          logger.info("userInfo");
          logger.info(UserAttributes);

          var params =  {
                        UserPoolId: userPoolId, // Your user pool id here
                        Username: userInfo["userName"],
                        UserAttributes: UserAttributes
                    };

         var cognitoidentityserviceprovider  = new AWS.CognitoIdentityServiceProvider({region:cognito_region,
                      accessKeyId: cognito_accessKeyId,
                      secretAccessKey: cognito_secretAccessKey,
                      poolId: cognito_poolId});

          cognitoidentityserviceprovider.adminUpdateUserAttributes(params, function(err, data)
          {
              if (err)
              {
                  logger.error("userInfo error");
                  logger.error(err);
                  resolve(err);
              }
              else
              {
                  logger.info(data);
                  delete params["UserAttributes"];
                  resolve(updateandSendUserInfo(cognitoidentityserviceprovider, params));
              }
          });

  });
}

function updateandSendUserInfo(cognitoidentityserviceprovider, params) {

    return new Promise(resolve => {
        cognitoidentityserviceprovider.adminGetUser(params, function(err, userAttributes)
        {
            if (err) {
                logger.error("userInfo error");
                logger.error(err);
                resolve(err);
            }
            else {

              logger.info("userAttributes ********");
              logger.info(userAttributes);
              linkCognitoUserWithLocalDatabase(userAttributes["UserAttributes"], false).then(userLocalInfo => {
                 logger.info(userLocalInfo);
                 var responseDict = {};
                 responseDict["userInfo"] = userLocalInfo;
                 resolve(responseDict);
              });
            }
        });

    });

}

function linkCognitoUserWithLocalDatabase(userInfo, isLoginSuccess) {

    return new Promise(resolve => {

        logger.info("userInfo");
        logger.info(userInfo);
        var userInfoDict = {};

        for (i = 0; i < userInfo.length; i++) {
            attrName = userInfo[i].Name;
            attrValue = userInfo[i].Value;
            logger.info('attribute ' + attrName + ' has value ' + attrValue);

            if (attrName == 'sub') {
                userInfoDict["congito_user_sub"] = attrValue;
                logger.info('congito_user_sub ' + attrValue);
            }
            if (attrName == 'phone_number') {
                userInfoDict["phone_number"] = attrValue;
                logger.info('phone_number ' + attrValue);
            }
            if (attrName == 'custom:last_name') {
                userInfoDict["last_name"] = attrValue;
                logger.info('last_name ' + attrValue);
            }
            if (attrName == 'custom:first_name') {
                userInfoDict["first_name"] = attrValue;
                logger.info('first_name ' + attrValue);
            }
            if (attrName == 'name') {
                userInfoDict["email"] = attrValue;
                userInfoDict["user_name"] = attrValue;
                logger.info('name ' + attrValue);
            }
            if (attrName == 'custom:userrole') {
                userInfoDict["role"] = attrValue;
                logger.info('userrole ' + attrValue);
            }
        }

        userInfoDict["login_time"] = db.fn.now(); // For update login time
        var tablename = "dashboard_users";
        var user_id = "dashboard_user_id";

        logger.info("userrole " + userInfoDict["role"]);
        var userRole = userInfoDict["role"];




    });

}


function forgotPassword(userInfo) {

  return new Promise(resolve => {

            var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
            var userData =
            {
                Username : userInfo["userName"],
                Pool : userPool
            };
            var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
            cognitoUser.forgotPassword (
            {
                onSuccess: function (result)
                {
                    logger.info('result: ');
                    logger.info(result);
                    resolve(result);
                },
                onFailure: function(err)
                {
                    logger.error('err: ');
                    logger.error(err);
                    resolve(err);
                },
                inputVerificationCode : function()
                {
                    var body = {};
                    body["error"] = {"message" : "inputVerificationCode"};
                    resolve(body);
                }
            });
      });
}

function resetPassword(userInfo) {
  return new Promise(resolve => {

            var verificationCode =  userInfo["verificationCode"];
            var newPassword =  userInfo["newPassword"];
            var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
            var userData =
            {
                Username : userInfo["userName"],
                Pool : userPool
            };
            var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
            cognitoUser.confirmPassword(verificationCode, newPassword,   {
                  onSuccess: function (result)
                  {
                      logger.info('result: ');
                      logger.info(result);
                      resolve(result);
                  },
                  onFailure: function(err)
                  {
                      logger.error('err: ');
                      logger.error(err);
                      resolve(err);
                  }
            });

      });
}

function deleteCognitoUser(userInfo) {

    return new Promise(resolve => {
        logger.info("userInfo");
        logger.info(userInfo);

        var params = {
            UserPoolId: userPoolId,
            Username: userInfo["userName"]
        };

        var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({
            region: cognito_region,
            accessKeyId: cognito_accessKeyId,
            secretAccessKey: cognito_secretAccessKey,
            poolId: cognito_poolId
        });

        cognitoidentityserviceprovider.adminDeleteUser(params, function (err, data) {
            var body = {};

            if (err) {
                logger.error(err.message);
                body["error"] = { "message": err.message };
                resolve(body)
            } else {
                logger.info(data);
                resolve(deleteUserDataInDB(userInfo["userName"], userInfo["role"]));
            }
        });
    });
}

function deleteUserDataInDB(email, userRole){
    return new Promise(resolve => {
        var body = {};
        var tablename = "dashboard_users";

        logger.info("userrole " + userRole);

    });
}

function disableCognitoUser(userInfo) {
    return new Promise(resolve => {
        logger.info("userInfo");
        logger.info(userInfo);

        var params = {
            UserPoolId: userPoolId,
            Username: userInfo["userName"]
        };

        var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({
            region: cognito_region,
            accessKeyId: cognito_accessKeyId,
            secretAccessKey: cognito_secretAccessKey,
            poolId: cognito_poolId
        });

        cognitoidentityserviceprovider.adminDisableUser(params, function (err, data) {
            var body = {};
            var userInfoDict = {};
            var tablename = "dashboard_users";
            var userRole = userInfo["role"];
            if (userRole == DELEIVERY_BOY_ROLE) {
                tablename = "delivery_boy";
            }

            if (err) {
                logger.error(err.message);
                body["error"] = { "message": err.message };
                resolve(body)
            } else {
                logger.info(data);
                body["success"] = true;
                //resolve(body);
                userInfoDict["user_status"] = 2; // Disable user

            }
        });
    });
}

function enableCognitoUser(userInfo) {
    return new Promise(resolve => {
        logger.info("userInfo");
        logger.info(userInfo);

        var params = {
            UserPoolId: userPoolId,
            Username: userInfo["userName"]
        };

        var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({
            region: cognito_region,
            accessKeyId: cognito_accessKeyId,
            secretAccessKey: cognito_secretAccessKey,
            poolId: cognito_poolId
        });

        cognitoidentityserviceprovider.adminEnableUser(params, function (err, data) {
            var body = {};
            var userInfoDict = {};
            var tablename = "dashboard_users";
            var userRole = userInfo["role"];
            if (userRole == DELEIVERY_BOY_ROLE) {
                tablename = "delivery_boy";
            }

            if (err) {
                logger.error(err.message);
                body["error"] = { "message": err.message };
                resolve(body)
            } else {
                logger.info(data);
                body["success"] = true;
                //resolve(body);
                userInfoDict["user_status"] = 3; // Enable user
                db(tablename)
                    .where('user_name', userInfo["userName"])
                    .update(userInfoDict)
                    .then(() => {
                        logger.info("user updated");
                        resolve(body);
                    });
            }
        });
    });
}

function getAccessToken(userInfo) {
    return new Promise(resolve => {
        logger.info("userInfo");
        logger.info(userInfo);

        var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
        var CognitoRefreshToken = AmazonCognitoIdentity.CognitoRefreshToken;
        var userData =
        {
            Username: userInfo["userName"],
            Pool: userPool
        };

        var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

        var token = new CognitoRefreshToken({ RefreshToken: userInfo["refreshtoken"] })
        cognitoUser.refreshSession(token, (err, session) => {

            var body = {};

            if (err) {
                logger.error(err.message);
                body["error"] = { "message": err.message };
                resolve(body)
            } else {
                logger.info(session);
                resolve(session)
            }
        });
    });
}

function resendTemporaryPassword(userInfo) {
    return new Promise(resolve => {
        logger.info("resendTemporaryPassword called");
        var body = {};
        var UserAttributes = [
            {
                Name: 'email', Value: userInfo["userName"]
            }
        ]

        var params =
        {
            UserPoolId: userPoolId, // Your user pool id here
            Username: userInfo["userName"],
            DesiredDeliveryMediums:
                ["EMAIL", "SMS"],
            MessageAction: 'RESEND',
            UserAttributes: UserAttributes
        };

        var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({
            region: cognito_region,
            accessKeyId: cognito_accessKeyId,
            secretAccessKey: cognito_secretAccessKey,
            poolId: cognito_poolId
        });

        cognitoidentityserviceprovider.adminCreateUser(params, function (err, data) {

            if (err) {
                body = err;
                logger.error("resendTemporaryPassword error");
                logger.error(err);
            }
            else {
                body["statusCode"] = 200;
            }
            logger.info("resendTemporaryPassword completion");

            body["success"] = true;
            //resolve(err, data);
            resolve(body);
        });
    });
}

async function isAuthorized(accessToken) {
    try {
        //logger.info(accessToken);
        await jwtVerifier.verify(accessToken);
    } catch (error) {
        logger.error(error);
        return {
            error: error,
            status: "403",
            message: "Unauthorized",
        };
    }
    return {
        status: "200",
        message: "Authorized",
    }; // allow request to proceed
}



module.exports = {
    createUser,
    signup,
    signupVerify,
    login,
    forgotPassword,
    resetPassword,
    updateAttributes,
    deleteCognitoUser,
    disableCognitoUser,
    enableCognitoUser,
    getAccessToken,
    resendTemporaryPassword,
    isAuthorized
};
