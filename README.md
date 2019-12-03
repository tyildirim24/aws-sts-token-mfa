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
- **MFA Device ARN**		Multi factor authentication device ARN i.e. arn:aws:iam::123456789012:**mfa**/user (you can find this in IAM)
- **Permanent AWS Access Key**		Your permanent AWS access key
- **Permanent AWS Secret Key**		Your permanent AWS secret key
- **Profile name**		Profile name that the temporary credentials will be saved for (you can type default or any other profile name)
-**Duration**		Duration of the temporary token in seconds. You can enter any value between 900-129600 (15 minutes to 36 hours)
- **Token code**		6 digit token code from your device

If you select to, these are saved to *./config/defaults.json* file. **YOU SHOULD PROTECT THIS FILE BEACUSE IT CONTAINS YOUR PERMANENT AWS KEYS!!!**

After you save these, app will use these values as defaults and let you select them by just hitting enter key in consecutive runs. If you change any parameter, app will prompt you to save changes.

If you select not to save the defaults, you will need to enter these values every time.

This program also removes the profiles whose token expired. It displays deleted profiles info on command prompt.

## Command line arguments
`$ ./aws-sts-token-mfa -skip` or `$ ./aws-sts-token-mfa -s`  will skip all parameter entries and use defaults

`$ ./aws-sts-token-mfa -t 123456` or `$ ./aws-sts-token-mfa -t 123456` will get token code from arguments and don't ask during parameter entry. You will still need to enter other parameters. (Replace 123456 with token code from your device)

`$ ./aws-sts-token-mfa -s -t 123456` will get token code and skip parameters and get temporary token with one command using the defaults.

`$ ./aws-sts-token-mfa -r arn:aws:iam::123456789012:role/my-role` or `$ ./aws-sts-token-mfa -role arn:aws:iam::123456789012:role/my-role`  will generate token for the given profile and also create another profile which assumes the given role. New role name format is {profile_name}-assumed-{role_name} (i.e. default-assumed-my-role). Name of this new assumed role profile is printed on command line.

