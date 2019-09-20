# aws-sts-token-mfa
A Go application to make retrieval of AWS temporary tokens from STS service easy when using Multi Factor Authentication (MFA)


## building & running the application
``` sh
$ go get -d ./...
$ go run main.go
$ go build -o aws-token-sts-mfa
```

# Usage
First time the application is run, it will ask for required parameters. At the end of parameter entry, application asks the user if they want to save these parameters so that they can be used in consecutive runs as defaults.

Parameters:
- **Region**		AWS region
- **MFA Device ARN**		Multi factor authentication device ARN (you can find this in IAM)
- **Permanent AWS Access Key**		Your permanent AWS access key
- **Permanent AWS Secret Key**		Your permanent AWS secret key
- **Profile name**		Profile name that the temporary credentials will be saved for (you can type default or any other profile name)
-**Duration**		Duration of the temporary token in seconds. You can enter any value between 900-129600 (15 minutes to 36 hours)
- **Token code**		6 digit token code from your device

If you select to, these are saved to *./config/defaults.json* file. **YOU SHOULD PROTECT THIS FILE BEACUSE IT CONTAINS YOUR PERMANENT AWS KEYS!!!**

After you save these, app will use these values as defaults and let you select them by just hitting enter key in consecutive runs. If you change any parameter, app will prompt you to save changes.

If you select not to save the defaults, you will need to enter these values every time.

## Command line arguments
`$ ./aws-sts-token-mfa -skip` or `$ ./aws-sts-token-mfa -s`  will skip all parameter and entries and use defaults

`$ ./aws-sts-token-mfa -t 123456` or `$ ./aws-sts-token-mfa -t 123456` will get token code from your device from arguments and don't ask (considering your token code is 123456)

`$ ./aws-sts-token-mfa -s -t 123456`will get token code and skip parameters and get temporary token with one command using the defaults.

