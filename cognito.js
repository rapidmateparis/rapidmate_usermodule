const express = require('express'),
      router = express.Router();

const cognitoservice = require('./cognitoservice');
const logger = require('log4js').getLogger(require('path').basename(__filename));

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});

app.post('/create', async function (req, res, next) {

    logger.info('/create');
    if(req.body) {
        logger.info('/create request', req.body)
    }

    var isAuththorized = await cognitoservice.isAuthorized(req.headers.authorization);
    if (isAuththorized.status == 200) {
        if (!req.body) {
            logger.error(' /create Status 400 Invalid request format')
            return res.status(400).json({ error: 'Invalid request format' });
        }

        const email = req.body.info.userName;
        if (!email) {
            logger.error('create : Email is required')
            return res.status(400).json({ error: 'Email is required' });
        }

        cognitoservice.createUser(req.body.info).then(user => {
            logger.info('/create response',user)
            return res.json(user);
        }).catch(function (e) {
            console.log(e);
            logger.error('/create error',e)
            return res.status(500).json(e);
        });
    }
    else {
        logger.error('/create status 401 Unauthorized')
        return res.status(401).json({ message: 'Unauthorized' });
    }
});

app.post('/signup', function (req, res, next) {

    console.log("signup");
    console.log(req);
      console.log(req.body);
    if(req.body) {
        logger.info('/signup request', req.body)
    }
    else {
        logger.error(' /signup Status 400 Invalid request format')
        return res.status(400).json({error: 'Invalid request format'});
    }

    cognitoservice.signup(req.body.info).then(user => {
        logger.info('/signup response',user)
        return res.json(user);
    }).catch(next);
});

app.post('/signupVerify', function (req, res, next) {

    console.log("signup");
    console.log(req);
      console.log(req.body);
    if(req.body) {
        logger.info('/signupVerifysignupVerify request', req.body)
    }
    else {
        logger.error(' /signupVerify Status 400 Invalid request format')
        return res.status(400).json({error: 'Invalid request format'});
    }

    cognitoservice.signupVerify(req.body.info).then(user => {
        logger.info('/signupVerify response',user)
        return res.json(user);
    }).catch(next);
});


app.post('/login', function (req, res, next) {

    if(req.body) {
        logger.info('/login request', req.body)
    }
    else {
        logger.error(' /login Status 400 Invalid request format')
        return res.status(400).json({error: 'Invalid request format'});
    }

    cognitoservice.login(req.body.info).then(user => {
        logger.info('/login response',user)
        return res.json(user);
    }).catch(next);
});

router.put('/update', async function (req, res, next) {

    logger.info('/cognito update');
    if(req.body) {
        logger.info('/cognito update request', req.body)
    }

    var isAuththorized = await cognitoservice.isAuthorized(req.headers.authorization);
    if (isAuththorized.status == 200) {
        if (!req.body) {
            logger.error('/cognito update Status 400 Invalid request format')
            return res.status(400).json({ error: 'Invalid request format' });
        }

        cognitoservice.updateAttributes(req.body.info).then(user => {
            logger.info('/cognito update response',user)
            return res.json(user);
        }).catch(next);
    }
    else {
        logger.error('/cognito update status 401 Unauthorized')
        return res.status(401).json({ message: 'Unauthorized' });
    }
});

router.post('/forgotPassword', function (req, res, next) {

  if(req.body) {
    logger.info('/forgotPassword request', req.body)
  }else{
    logger.error('/forgotPassword Status 400 Invalid request format')
    return res.status(400).json({error: 'Invalid request format'});
  }

  cognitoservice.forgotPassword(req.body.info).then(user => {
    if (!user) {
      logger.error('/forgotPassword Status 401 Invalid user or password')
      return res.status(401).json({error: 'Invalid user or password'});
    }
    logger.info('/forgotPassword response',user)
    return res.json(user);
  }).catch(next);
});

router.post('/resetPassword', function (req, res, next) {

  if(req.body) {
    logger.info('/resetPassword request', req.body)
  }else{
    logger.error('/resetPassword Status 400 Invalid request format')
    return res.status(400).json({error: 'Invalid request format'});
  }

  cognitoservice.resetPassword(req.body.info).then(user => {
    if (!user) {
      logger.error('/resetPassword Status 401 Invalid user or password')
      return res.status(401).json({error: 'Invalid user or password'});
    }
    logger.info('/resetPassword response',user)
    return res.json(user);
  }).catch(next);
});

router.post('/delete', async function (req, res, next) {

    logger.info('/delete')
    if(req.body) {
        logger.info('/delete request', req.body)
    }

    var isAuththorized = await cognitoservice.isAuthorized(req.headers.authorization);
    if (isAuththorized.status == 200) {
        if (!req.body) {
            logger.error('/delete Status 400 Invalid request format')
            return res.status(400).json({ error: 'Invalid request format' });
        }

        cognitoservice.deleteCognitoUser(req.body.info).then(user => {
            logger.info('/delete response',user)
            return res.json(user);
        }).catch(next);
    }
    else {
        logger.error('/delete status 401 Unauthorized')
        return res.status(401).json({ message: 'Unauthorized' });
    }
});

router.post('/disableUser', async function (req, res, next) {

    logger.info('/disableUser');
    if(req.body) {
        logger.info('/disableUser request', req.body)
    }

    var isAuththorized = await cognitoservice.isAuthorized(req.headers.authorization);
    if (isAuththorized.status == 200) {
        if (!req.body) {
            logger.error('/disableUser Status 400 Invalid request format')
            return res.status(400).json({ error: 'Invalid request format' });
        }
        cognitoservice.disableCognitoUser(req.body.info).then(user => {
            logger.info('/disableUser response',user)
            return res.json(user);
        }).catch(next);
    }
    else {
        logger.error('/disableUser status 401 Unauthorized')
        return res.status(401).json({ message: 'Unauthorized' });
    }
});

router.post('/enableUser', async function (req, res, next) {

    logger.info('/enableUser');
    if(req.body) {
        logger.info('/enableUser request', req.body)
    }

    var isAuththorized = await cognitoservice.isAuthorized(req.headers.authorization);
    if (isAuththorized.status == 200) {
        if (!req.body) {
            logger.error('/enableUser Status 400 Invalid request format')
            return res.status(400).json({ error: 'Invalid request format' });
        }

        cognitoservice.enableCognitoUser(req.body.info).then(user => {
            logger.info('/enableUser response',user)
            return res.json(user);
        }).catch(next);
    }
    else {
        logger.error('/enableUser status 401 Unauthorized')
        return res.status(401).json({ message: 'Unauthorized' });
    }
});

router.put('/resend', async function (req, res, next) {

    logger.info('/resend');
    if(req.body) {
        logger.info('/resend request', req.body)
    }

    var isAuththorized = await cognitoservice.isAuthorized(req.headers.authorization);
    if (isAuththorized.status == 200) {
        if (!req.body) {
            logger.error('/resend Status 400 Invalid request format')
            return res.status(400).json({ error: 'Invalid request format' });
        }

        cognitoservice.resendTemporaryPassword(req.body.info).then(user => {
            logger.info('/resend response',user)
            return res.json(user);
        }).catch(next);
    }
    else {
        logger.error('/resend status 401 Unauthorized')
        return res.status(401).json({ message: 'Unauthorized' });
    }
});

router.post('/getAccessToken', function (req, res, next) {
    if(req.body) {
        logger.info('/getAccessToken request', req.body)
    }
    else {
        logger.error('/getAccessToken Status 400 Invalid request format');
        return res.status(400).json({ error: 'Invalid request format' });
    }

    cognitoservice.getAccessToken(req.body.info).then(user => {
        logger.info('/getAccessToken response',user)
        return res.json(user);
    }).catch(next);
});



module.exports = router;
