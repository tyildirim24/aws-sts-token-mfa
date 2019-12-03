package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

type temporaryCredential struct {
	ProfileName   string
	AssumedRole   string
	AccessKeyID   string
	SecretKeyID   string
	SessionToken  string
	SecurityToken string
	Expiration    time.Time
}

type defaultData struct {
	ProfileName string `json:"profileName"`
	DeviceARN   string `json:"deviceARN"`
	AccessKeyID string `json:"accessKeyID"`
	SecretKey   string `json:"secretKey"`
	Token       string `json:"token"`
	Duration    int64  `json:"durationInSeconds"`
	Region      string `json:"awsRegion"`
}

var defaults defaultData
var tokenCode string
var awsConfigDirectory string
var awsCredentialsFilePath string
var awsConfigFilePath string
var roleARN string

const (
	// set defaults for config folder and file name
	configFolderPath = "./config"
	defaultsFileName = "defaults.json"
	defaultsFilePath = configFolderPath + "/" + defaultsFileName
)

func main() {

	args := os.Args[1:]

	tokenCode := getTokenCodeFromArgs(&args)

	roleARN = getRoleArnFromArgs(&args)

	setAwsConfigFilePaths()

	//load default data from json file if it existst
	loadDefaults()

	// read parameters if there is no skip argument "-skip"
	if !argsContainSkip(&args) {
		// read required params from command line
		readParameters()
	}

	if len(tokenCode) != 6 {
		// read the token code from mfa device until it's valid code
		var err error
		tokenCode, err = readValueFromCli("Token code from your device: ")
		for err != nil || len(tokenCode) != 6 {
			fmt.Println("Please enter a valid 6 digit token code from your MFA device!")
			tokenCode, err = readValueFromCli("Token code from your device: ")
		}
	}

	// create aws session and get temporary credentials
	mySession, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String(defaults.Region),
			Credentials: credentials.NewStaticCredentials(defaults.AccessKeyID, defaults.SecretKey, defaults.Token),
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	stsSvc := sts.New(mySession)

	var getTokenInput sts.GetSessionTokenInput

	getTokenInput.SetSerialNumber(defaults.DeviceARN)
	getTokenInput.SetTokenCode(tokenCode)
	getTokenInput.SetDurationSeconds(defaults.Duration)

	token, err := stsSvc.GetSessionToken(&getTokenInput)

	if err != nil {
		log.Fatal(err)
	}

	// format credentials received and write it to aws credentials file.
	creds := temporaryCredential{
		ProfileName:   defaults.ProfileName,
		AssumedRole:   "False",
		AccessKeyID:   *token.Credentials.AccessKeyId,
		SecretKeyID:   *token.Credentials.SecretAccessKey,
		SessionToken:  *token.Credentials.SessionToken,
		SecurityToken: *token.Credentials.SessionToken,
		Expiration:    *token.Credentials.Expiration,
	}

	log.Printf("\n%+v\n\n", creds)

	writeToAwsCredentialsFile(&creds, awsCredentialsFilePath)

	// if it doesn't exist, create entry for the selected profile on aws config file
	writeToAwsConfigFile(&creds, awsConfigFilePath)
}

func getTokenCodeFromArgs(args *[]string) string {
	for i := 0; i < len(*args); i++ {
		if strings.ToLower((*args)[i]) == "-token" || strings.ToLower((*args)[i]) == "-t" {
			if len(*args) > (i + 1) {
				token := strings.Replace((*args)[i+1], "\n", "", -1)
				token = strings.Replace(token, "\r", "", -1)
				if len(token) != 6 {
					log.Fatal("Token from MFA device must be 6 characters long")
				} else {
					return token
				}
			} else {
				log.Fatal("Token from MFA device must be given after -t or -token parameter")
			}
		}
	}
	return ""
}

func getRoleArnFromArgs(args *[]string) string {
	for i := 0; i < len(*args); i++ {
		if strings.ToLower((*args)[i]) == "-role" || strings.ToLower((*args)[i]) == "-r" {
			if len(*args) > (i + 1) {
				role := strings.Replace((*args)[i+1], "\n", "", -1)
				role = strings.Replace(role, "\r", "", -1)
				if len(role) <= 32 {
					log.Fatal("Role ARN must be at least 32 characters long")
				} else {
					return role
				}
			} else {
				log.Fatal("Assume role Role-ARN must be given after -r or -role parameter")
			}
		}
	}
	return ""
}

func argsContainSkip(args *[]string) bool {
	for _, arg := range *args {
		if strings.ToLower(arg) == "-skip" || strings.ToLower(arg) == "-s" {
			return true
		}
	}
	return false
}

// set aws config file paths and create folder if it odesn't exist
func setAwsConfigFilePaths() {
	// get user home directory from os and set aws config and credentials file paths
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	awsConfigDirectory = usr.HomeDir + "/.aws"
	awsConfigFilePath = awsConfigDirectory + "/config"
	awsCredentialsFilePath = awsConfigDirectory + "/credentials"

	if !directoryExists(awsConfigDirectory) {
		err := os.MkdirAll(awsConfigDirectory, 0744)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func loadDefaults() {

	if !directoryExists(configFolderPath) {
		err := os.MkdirAll(configFolderPath, 0744)
		if err != nil {
			log.Fatal(err)
		}
	}

	if !fileExists(defaultsFilePath) {
		defaults = defaultData{}
		saveDefaultsAsJSONFile()
	}

	defaultsFile, err := os.Open(defaultsFilePath)

	if err != nil {
		log.Fatal(err)
	}

	defer defaultsFile.Close()

	byteValue, err2 := ioutil.ReadAll(defaultsFile)

	if err2 != nil {
		log.Fatal(err2)
	}

	err = json.Unmarshal(byteValue, &defaults)

	if err != nil {
		log.Fatal(err)
	}
}

func readParameters() {

	defaultsChanged := false

	text, err := readValueFromCli(fmt.Sprintf("Region (%s): ", defaults.Region))
	if err == nil {
		defaults.Region = text
		defaultsChanged = true
	}

	text, err = readValueFromCli(fmt.Sprintf("Device arn (%s): ", defaults.DeviceARN))
	if err == nil {
		defaults.DeviceARN = text
		defaultsChanged = true
	}

	text, err = readValueFromCli(fmt.Sprintf("Permanent AWS Access Key (%s): ", defaults.AccessKeyID))
	if err == nil {
		defaults.AccessKeyID = text
		defaultsChanged = true
	}

	text, err = readValueFromCli(fmt.Sprintf("Permanent AWS Secret Key (%s): ", defaults.SecretKey))
	if err == nil {
		defaults.SecretKey = text
		defaultsChanged = true
	}

	// text, err = readValueFromCli(fmt.Sprintf("Permanent AWS Access Token (leave empty if token not required) (%s): ", defaults.Token))
	// if err == nil {
	// 	defaults.Token = text
	// 	defaultsChanged = true
	// }

	text, err = readValueFromCli(fmt.Sprintf("Profile name for temporary credentials to save into (%s): ", defaults.ProfileName))
	if err == nil {
		defaults.ProfileName = text
		defaultsChanged = true
	}

	expired, tm := didTokenInCredentialsFileExpired(awsCredentialsFilePath, defaults.ProfileName)
	if !expired {
		msg := fmt.Sprintf("Your credentials for the profile [%s] is not expired yet! It will expire at %s. Would you like to refresh it (y/n): ", defaults.ProfileName, tm)
		text = ""
		for strings.ToLower(text) != "y" && strings.ToLower(text) != "n" {
			text, err = readValueFromCli(msg)
		}
		if strings.ToLower(text) == "n" {
			fmt.Println("Exiting because existing token is still valid and the user selected NOT to refresh it!")
			os.Exit(0)
		}
	}

	durationValid := false
	for !durationValid {
		text, err = readValueFromCli(fmt.Sprintf("Duration in seconds (%d): ", defaults.Duration))
		if err == nil {
			n, e := strconv.ParseInt(text, 10, 64)
			if e == nil {
				// check if duration is between 15 minutes and 36 hours (aws limits) in seconds
				if n >= 900 && n <= 129600 {
					defaults.Duration = n
					defaultsChanged = true
					durationValid = true
				} else {
					fmt.Printf("\t Invalid duration! Please eneter a numeric value between 900-129600\n")
				}
			} else {
				fmt.Printf("\t Invalid duration! Please eneter a numeric value between 900-129600\n")
			}
		} else {
			durationValid = true
		}
	}

	if defaultsChanged {

		text, err = readValueFromCli("\nYou have changed the configuration value(s). Would you like to save changes to defaults [yes/no, y/n] (no): ")
		if err == nil && (strings.ToLower(text) == "y" || strings.ToLower(text) == "yes") {
			saveDefaultsAsJSONFile()
		}
	}
}

func saveDefaultsAsJSONFile() {
	jsonData, err := json.Marshal(defaults)
	if err != nil {
		log.Fatal(err)
	}

	jsonFile, err := os.Create(defaultsFilePath)

	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()

	jsonFile.Write(jsonData)
}

func readValueFromCli(message string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf(message)
	text, _ := reader.ReadString('\n')
	// convert CRLF to LF
	text = strings.Replace(text, "\n", "", -1)
	text = strings.Replace(text, "\r", "", -1)
	if len(text) < 1 {
		err := errors.New("No value")
		return "", err
	}
	return text, nil
}

func writeToAwsConfigFile(creds *temporaryCredential, filePath string) {

	profilesInConfigFile := getProfilesFromFile(filePath)
	roleProfileName := ""

	text := fmt.Sprintf("[profile %s]\n", creds.ProfileName)
	text += fmt.Sprintf("region = %s\n", defaults.Region)
	text += "output=json\n"
	text += "\n"

	if len(roleARN) > 0 {
		roleProfileName = getAssumedProfileNameFromARN(roleARN, defaults.ProfileName)
		text += fmt.Sprintf("[profile %s]\n", roleProfileName)
		text += fmt.Sprintf("region = %s\n", defaults.Region)
		text += "output=json\n"
		text += "\n"
	}

	//if default profile doesn't exists, create it. aws cli will crash
	if creds.ProfileName != "default" {
		if _, ok := profilesInConfigFile["profile default"]; !ok {
			text += "[profile default]\n"
			text += fmt.Sprintf("region = %s\n", defaults.Region)
			text += "output=json\n"
			text += "\n"
		}
	}

	credsFile, err := os.Create(filePath)

	if err != nil {
		log.Fatal(err)
	}
	defer credsFile.Close()

	_, err = io.WriteString(credsFile, text)
	if err != nil {
		log.Fatal(err)
	}

	for key, val := range profilesInConfigFile {
		if key != fmt.Sprintf("profile %s", creds.ProfileName) && key != fmt.Sprintf("profile %s", roleProfileName) {
			text = fmt.Sprintf("[%s]\n", key)
			for key2, val2 := range val {
				text += fmt.Sprintf("%s = %s\n", key2, val2)
			}
			text += "\n"
			_, err = io.WriteString(credsFile, text)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	err = credsFile.Sync()

	if err != nil {
		log.Fatal(err)
	}

}

func writeToAwsCredentialsFile(creds *temporaryCredential, filePath string) {

	profilesInCredsFile := getProfilesFromFile(filePath)

	roleProfileName := ""

	text := fmt.Sprintf("[%s]\n", creds.ProfileName)
	//text += fmt.Sprintf("assumed_role = %s\n", creds.AssumedRole)
	text += fmt.Sprintf("aws_access_key_id = %s\n", creds.AccessKeyID)
	text += fmt.Sprintf("aws_secret_access_key = %s\n", creds.SecretKeyID)
	text += fmt.Sprintf("aws_session_token = %s\n", creds.SessionToken)
	text += fmt.Sprintf("aws_security_token = %s\n", creds.SecurityToken)
	text += fmt.Sprintf("expiration = %s\n", creds.Expiration.Format(time.RFC1123Z))
	text += "\n"
	if len(roleARN) > 0 {
		roleProfileName = getAssumedProfileNameFromARN(roleARN, defaults.ProfileName)
		text += fmt.Sprintf("[%s]\n", roleProfileName)
		text += fmt.Sprintf("role_arn = %s\n", roleARN)
		text += fmt.Sprintf("source_profile = %s\n", creds.ProfileName)
		text += "\n"
	}

	credsFile, err := os.Create(filePath)

	if err != nil {
		log.Fatal(err)
	}
	defer credsFile.Close()

	_, err = io.WriteString(credsFile, text)
	if err != nil {
		log.Fatal(err)
	}

	for key, val := range profilesInCredsFile {
		if key != creds.ProfileName && key != roleProfileName {
			//Keep the existing credentials only if they are not expired
			if !didCredsExpire(val) {
				text = fmt.Sprintf("[%s]\n", key)
				for key2, val2 := range val {
					text += fmt.Sprintf("%s = %s\n", key2, val2)
				}
				text += "\n"
				_, err = io.WriteString(credsFile, text)
				if err != nil {
					log.Fatal(err)
				}
			} else {
				log.Printf("Credentials for %s expired at %s. Removing this profile!\n", key, val["expiration"])
			}
		}
	}

	err = credsFile.Sync()

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\nCredentials saved to %s Token will expire at %s\n", filePath, creds.Expiration)
	if len(roleARN) > 0 {
		fmt.Println("\n==================================================")
		fmt.Printf("A new profile [%s] which assumes role %s is created. You can assume this role by appending '--profile %s' to cli commands.\n", roleProfileName, roleARN, roleProfileName)
		userARN := strings.Replace(defaults.DeviceARN, "mfa", "user", 1)
		fmt.Printf("Make sure that %s is authorized for sts:AssumeRole on %s and this role's trust relationship policy has:\n", userARN, roleARN)

		warningText := `
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
			  	"AWS": "{{user_arn}}"
				},
				"Action": "sts:AssumeRole"
			},
			...
		]`

		fmt.Printf("%s\n", strings.Replace(warningText, "{{user_arn}}", userARN, 1))
		fmt.Println("==================================================")
	}
}

func getAssumedProfileNameFromARN(arn string, profile string) string {
	cols := strings.Split(arn, "/")
	return fmt.Sprintf("%s-assumed-%s", profile, cols[len(cols)-1])
}

func didCredsExpire(data map[string]string) bool {
	if expStr, ok := data["expiration"]; ok {
		tm, err := time.Parse(time.RFC1123Z, expStr)
		if err != nil {
			fmt.Println(err)
			return false
		}
		now := time.Now()
		_, offset := now.Zone()
		duration := time.Duration(offset)
		now = now.Add(duration)

		return now.After(tm)
	}
	return false
}

func didTokenInCredentialsFileExpired(credsFilePath string, profileName string) (bool, string) {

	credsMap := getProfilesFromFile(credsFilePath)

	if selectedProfileCreds, ok := credsMap[profileName]; ok {
		if expStr, ok2 := selectedProfileCreds["expiration"]; ok2 {
			tm, err := time.Parse(time.RFC1123Z, expStr)
			if err != nil {
				fmt.Println(err)
				return true, ""
			}
			now := time.Now()
			_, offset := now.Zone()
			duration := time.Duration(offset)
			now = now.Add(duration)

			expired := now.After(tm)
			if !expired {
				return false, expStr
			}
			return true, ""
		}
	}
	return true, ""
}

// fileExists checks if a file exists
func fileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return true
	}
	return !info.IsDir()
}

// directoryExists checks if a directory exists
func directoryExists(dirPath string) bool {
	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		return true
	}
	return info.IsDir()
}

func getProfilesFromFile(credsFilePath string) map[string]map[string]string {
	res := make(map[string]map[string]string)
	if !fileExists(credsFilePath) {
		return res
	}

	file, err := os.Open(credsFilePath)
	if err != nil {
		return res
	}
	defer file.Close()

	currentProfile := ""

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if (line != "") && line != "\n" {
			if line[0:1] == "[" && line[len(line)-1:] == "]" {
				currentProfile = strings.Replace(strings.Replace(line, "[", "", -1), "]", "", -1)
				res[currentProfile] = make(map[string]string)
			} else {
				if currentProfile != "" {
					ind := strings.Index(line, "=")
					if ind > 1 && ind < len(line) {
						key := strings.TrimSpace(line[0:ind])
						val := strings.TrimSpace(line[ind+1:])
						res[currentProfile][key] = val
					}
				}
			}
		}
	}
	return res
}
