# aws-sts-token-mfa
Go application to get AWS temporary tokens using Multi Factor Authentication (MFA)

# run
go run main.go

# build
go build main.go

# usage
Application will ask aws-region, permanent credentials (access key, secret key and token if needed), token expiration duration and profile name. If user selects to, these are saved so that it won't be asked again and again. Defaults are saved to ./config/defaults.json

If everything is right, app will get temporary credentials and save them on aws credentials file. 