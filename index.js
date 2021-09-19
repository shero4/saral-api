const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');

const dynamo = new AWS.DynamoDB.DocumentClient();
const s3 = new AWS.S3();//

const tableName = 'saral-aws-data';
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
var config = require('./config');
const qr = require('qrcode');

const verifyJWT = async (token) => {
    jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
            return false;
        }
        return decoded;
    });
}

const getUploadURL = async () => {
    const actionId = uuidv4()
    const s3Params = {
        Bucket: 'saral-data',
        Key:  `${actionId}.pdf`,
        ContentType: 'application/pdf',
        ACL: 'public-read',
    }
    return new Promise((resolve, reject) => {
    let uploadURL = s3.getSignedUrl('putObject', s3Params)
    resolve({
      "statusCode": 200,
      "isBase64Encoded": false,
      "headers": { "Access-Control-Allow-Origin": "*" },
      "body": JSON.stringify({
        "uploadURL": uploadURL,
        "fileName": `${actionId}.pdf`
      })
    })
  })
}

exports.handler = async (event) => {
    console.log(event)
    const eventData = JSON.parse(event.body);
    if(event.queryStringParameters) {
        var devid = event.queryStringParameters.data
        const dbparams = {
                TableName: tableName,
                Key: {
                    "deviceid": devid
                }
            }
        const uuuser = await dynamo.get(dbparams).promise();
        console.log(uuuser)
        if(uuuser.Item.reports.length == 0) {
            return {
                statusCode: 404,
                body: 'No reports found'
            }
        }
        console.log(uuuser.Item.reports[uuuser.Item.reports.length - 1].s3link)
        return {
            statusCode: 301,
            headers: {
                // LAST REPORT
                Location: uuuser.Item.reports[uuuser.Item.reports.length - 1].s3link,
            }
        }
    }
    const operation = eventData.operation;
    const payload = eventData.payload
    if(!operation || !payload) {
        return {
            statusCode: 500,
            body: 'invalid request'
        }
    }
    switch (operation) {
        case 'register':
            if (!payload.password || !payload.email || !payload.did) {
                return {
                    statusCode: 500,
                    body: 'invalid email or password'
                }
            }
            var did = payload.did
            var code = await qr.toDataURL('https://o6j3ryyzf3.execute-api.ap-south-1.amazonaws.com/default/api?data='+did);
            var buf = Buffer.from(code.replace(/^data:image\/\w+;base64,/, ""),'base64')
            console.log(code)
            var s3params = {
                Bucket: 'saral-data',
                Key: 'qrcode-'+did+'.png',
                Body: buf,
                ACL: "public-read",
                ContentEncoding: 'base64',
                ContentType: 'image/png'
             };
            const qrData = await s3.upload(s3params).promise();
            console.log(qrData)
            let params = {
                TableName: tableName,
                Item: {
                    deviceid: did,
                    email: payload.email,
                    password: bcrypt.hashSync(payload.password, 8),
                    reports: [],
                    healthParams: []
                }
            }
            await dynamo.put(params).promise();
            return {
                statusCode: 200,
                body: 'success'
            }
        case 'login':
            let p = {
                TableName: tableName,
                IndexName: "email",
                FilterExpression: "email = :email",
                ExpressionAttributeValues: {
                    ":email": payload.email
                },
            }
            let user = await dynamo.scan(p).promise();
            console.log(user);
            if(bcrypt.compareSync(payload.password, user.Items[0].password)) {
                var token = jwt.sign({ email: user.Items[0].email, deviceid: user.Items[0].deviceid }, config.secret, {
                  expiresIn: 86400 // expires in 24 hours
                });
                console.log(token)
                return { statusCode: 200, body: JSON.stringify({token, email: user.Items[0].email, deviceid: user.Items[0].deviceid}) };
            } else {
                return { statusCode: 500, body: 'invalid'};
            }
        case 'uploadReport':
            const retData = await getUploadURL();
            console.log(retData)
            var re = /^(.*?)\?/g
            var upURL = JSON.parse(retData.body).uploadURL
            var slicedURL = upURL.match(re)[0].slice(0, -1)
            const dparams = {
                TableName: tableName,
                Key: {
                    deviceid: payload.deviceid
                },
                ReturnValues: 'ALL_NEW',
                UpdateExpression : "SET #attrName = list_append(#attrName, :attrValue)",
                ExpressionAttributeNames : {
                  "#attrName" : "reports"
                },
                "ExpressionAttributeValues" : {
                  ":attrValue" : [{
                      s3link: slicedURL
                  }]
                }
            }
            console.log(dparams)
            await dynamo.update(dparams).promise();
            return retData;
        case 'me':
            const dbparams = {
                TableName: tableName,
                IndexName: "email",
                FilterExpression: "email = :email",
                ExpressionAttributeValues: {
                    ":email": payload.email
                },
            }
            const uuser = await dynamo.scan(dbparams).promise();
            delete uuser.Items[0].password
            return {
                statusCode: 200,
                body: JSON.stringify(uuser.Items[0])
            }
        default:
            throw new Error(`Unrecognized operation "${operation}"`);
    }
};
