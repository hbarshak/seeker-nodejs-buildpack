package hooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudfoundry/libbuildpack"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
)

const (
	EntryPointFile    = "SEEKER_APP_ENTRY_POINT"
	agentDownloadPath = "/rest/api/latest/installers/agents/binaries/NODEJS"
	SeekerRequire     = "require('./seeker/node_modules/@synopsys-sig/seeker');\n"
)

var pattern = regexp.MustCompile(`require\(['"].*@synopsys-sig/seeker['"]\)`)

type SeekerCommand interface {
	Execute(dir string, stdout io.Writer, stderr io.Writer, program string, args ...string) error
}

type Downloader interface {
	DownloadFile(url, destFile string) error
}

type Unzipper interface {
	Unzip(zipFile, absoluteFolderPath string) error
}

type SeekerAfterCompileHook struct {
	libbuildpack.DefaultHook
	Log                *libbuildpack.Logger
	Command            SeekerCommand
	Downloader         Downloader
	Unzipper           Unzipper
}

type SeekerCredentials struct {
	SeekerServerURL string
}

func init() {
	logger := libbuildpack.NewLogger(os.Stdout)
	command := &libbuildpack.Command{}
	libbuildpack.AddHook(&SeekerAfterCompileHook{
		Log:        logger,
		Command:    command,
		Downloader: SeekerDownloader{},
		Unzipper:   SeekerUnzipper{},
	})
}

func (h SeekerAfterCompileHook) AfterCompile(compiler *libbuildpack.Stager) error {
	h.Log.Debug("Seeker - AfterCompileHook Start")
	c := SeekerCredentials{}
	var err error
	if c, err = extractServiceCredentialsUserProvidedService(); err != nil {
		return err
	}
	if c == (SeekerCredentials{}) {
		if c, err = extractServiceCredentials(); err != nil {
			return err
		}
	}
	if c.SeekerServerURL == "" {
		h.Log.Info("seeker integration is disabled (seeker_server_url is missing in service configuration)")
		return nil
	}

	if err = h.prependRequire(compiler); err != nil {
		return err
	}

	seekerLibraryToInstall, err := h.downloadAgent(c)
	if err != nil {
		return err
	}

	h.Log.Info("Before Installing seeker agent dependency")
	err = h.updateNodeModules(seekerLibraryToInstall, compiler.BuildDir())
	if err != nil {
		return err
	}
	h.Log.Info("After Installing seeker agent dependency")
	err = h.createSeekerEnvironmentScript(c, compiler)
	if err != nil {
		return errors.New("Error creating seeker-env.sh script: " + err.Error())
	}
	h.Log.Info("Done creating seeker-env.sh script")
	return nil
}

func (h SeekerAfterCompileHook) prependRequire(compiler *libbuildpack.Stager) error {
	entryPointPath := os.Getenv(EntryPointFile)
	if entryPointPath == "" {
		return nil
	}
	h.Log.Debug("Adding Seeker agent require to application entry point %s", entryPointPath)
	return h.addSeekerAgentRequire(compiler.BuildDir(), entryPointPath)
}

func (h SeekerAfterCompileHook) addSeekerAgentRequire(buildDir string, pathToEntryPointFile string) error {
	absolutePathToEntryPoint := filepath.Join(buildDir, pathToEntryPointFile)
	h.Log.Debug("Trying to prepend %s to %s", SeekerRequire, absolutePathToEntryPoint)
	c, err := ioutil.ReadFile(absolutePathToEntryPoint)
	if err != nil {
		return err
	}
	// do not require twice
	if pattern.Match(c) {
		return nil
	}
	return ioutil.WriteFile(absolutePathToEntryPoint, append([]byte(SeekerRequire), c...), 0644)
}

func (h SeekerAfterCompileHook) downloadAgent(serviceCredentials SeekerCredentials) (string, error) {
	parsedEnterpriseServerURL, err := url.Parse(serviceCredentials.SeekerServerURL)
	if err != nil {
		return "", err
	}
	parsedEnterpriseServerURL.Path = path.Join(parsedEnterpriseServerURL.Path, agentDownloadPath)
	agentDownloadAbsoluteURL := parsedEnterpriseServerURL.String()
	h.Log.Info("Agent download url %s", agentDownloadAbsoluteURL)
	seekerTempFolder, err := ioutil.TempDir(os.TempDir(), "seeker_tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(seekerTempFolder)
	seekerLibraryPath := filepath.Join(seekerTempFolder, "seeker-agent.tgz")
	agentZipAbsolutePath := path.Join(seekerTempFolder, "seeker-node-agent.zip")
	h.Log.Info("Downloading '%s' to '%s'", agentDownloadAbsoluteURL, agentZipAbsolutePath)
	if err = h.Downloader.DownloadFile(agentDownloadAbsoluteURL, agentZipAbsolutePath); err != nil {
		return "", err
	}
	err = h.Unzipper.Unzip(agentZipAbsolutePath, seekerTempFolder)
	if err != nil {
		return "", err
	}
	exists, err := libbuildpack.FileExists(seekerLibraryPath)
	if !exists || err != nil {
		return "", errors.New("Could not find " + seekerLibraryPath)
	}
	return seekerLibraryPath, err
}

func (h SeekerAfterCompileHook) updateNodeModules(pathToSeekerLibrary string, buildDir string) error {
	// No need to handle YARN, since NPM is installed even when YARN is the selected package manager
	h.Log.Debug("About to install seeker agent, build dir: %s, seeker package: %s", buildDir, pathToSeekerLibrary)
	var err error
	if os.Getenv("BP_DEBUG") != "" {
		err = h.Command.Execute(buildDir, os.Stdout, os.Stderr, "npm", "install", "--save", pathToSeekerLibrary, "--prefix", "seeker")
	} else {
		err = h.Command.Execute(buildDir, ioutil.Discard, ioutil.Discard, "npm", "install", "--save", pathToSeekerLibrary, "--prefix", "seeker")
	}
	if err != nil {
		h.Log.Error("npm install --save " + pathToSeekerLibrary + " --prefix seeker Error: " + err.Error())
		return err
	}
	return nil
}

func (h *SeekerAfterCompileHook) createSeekerEnvironmentScript(serviceCredentials SeekerCredentials, stager *libbuildpack.Stager) error {
	seekerEnvironmentScript := "seeker-env.sh"

	const seekerServerTemplate = "export SEEKER_SERVER_URL=%s\n"
	scriptContent := fmt.Sprintf(seekerServerTemplate, serviceCredentials.SeekerServerURL)
	stager.Logger().Info(seekerEnvironmentScript + " content: " + scriptContent)
	return stager.WriteProfileD(seekerEnvironmentScript, scriptContent)
}

func extractServiceCredentials() (SeekerCredentials, error) {
	var vcapServices map[string][]struct {
		Name         string `json:"name"`
		Label        string `json:"label"`
		InstanceName string `json:"instance_name"`
		BindingName  string `json:"binding_name"`
		Credentials  struct {
			EnterpriseServerUrl string `json:"enterprise_server_url"`
			SeekerServerUrl     string `json:"seeker_server_url"`
			SensorHost          string `json:"sensor_host"`
			SensorPort          string `json:"sensor_port"`
		} `json:"credentials"`
	}

	err := json.Unmarshal([]byte(os.Getenv("VCAP_SERVICES")), &vcapServices)
	if err != nil {
		return SeekerCredentials{}, fmt.Errorf("failed to unmarshal VCAP_SERVICES: %s", err)
	}

	var detectedCredentials []SeekerCredentials

	for _, services := range vcapServices {
		for _, service := range services {
			if isSeekerRelated(service.Name, service.Label, service.InstanceName) {
				credentials := SeekerCredentials{SeekerServerURL: service.Credentials.SeekerServerUrl}
				detectedCredentials = append(detectedCredentials, credentials)
			}
		}
	}

	found, err := assertZeroOrOneServicesExist(len(detectedCredentials))
	if err != nil {
		return SeekerCredentials{}, err
	}
	if found {
		return detectedCredentials[0], nil
	}
	return SeekerCredentials{}, nil
}

func assertZeroOrOneServicesExist(c int) (bool, error) {
	if c > 1 {
		return false, fmt.Errorf("expected to find 1 Seeker service but found %d", c)
	}
	return c == 1, nil
}

func extractServiceCredentialsUserProvidedService() (SeekerCredentials, error) {
	type UserProvidedService struct {
		BindingName interface{} `json:"binding_name"`
		Credentials struct {
			SeekerServerUrl string `json:"seeker_server_url"`
		} `json:"credentials"`
		InstanceName   string   `json:"instance_name"`
		Label          string   `json:"label"`
		Name           string   `json:"name"`
		SyslogDrainURL string   `json:"syslog_drain_url"`
		Tags           []string `json:"tags"`
	}

	var vcapServices struct {
		UserProvidedService []UserProvidedService `json:"user-provided"`
	} //`json:"VCAP_SERVICES"`

	vcapServicesString := os.Getenv("VCAP_SERVICES")
	err := json.Unmarshal([]byte(vcapServicesString), &vcapServices)
	if err != nil {
		return SeekerCredentials{}, fmt.Errorf("failed to unmarshal VCAP_SERVICES: %s", err.Error())
	}
	if len(vcapServices.UserProvidedService) == 0 {
		return SeekerCredentials{}, nil
	}

	var detectedCredentials []UserProvidedService

	for _, service := range vcapServices.UserProvidedService {
		if isSeekerRelated(service.Name, service.Label, service.InstanceName) {
			detectedCredentials = append(detectedCredentials, service)
		}
	}

	found, err := assertZeroOrOneServicesExist(len(detectedCredentials))
	if err != nil {
		return SeekerCredentials{}, err
	}
	if found {
		c := SeekerCredentials{
			SeekerServerURL: detectedCredentials[0].Credentials.SeekerServerUrl}
		return c, nil
	}
	return SeekerCredentials{}, nil
}

func isSeekerRelated(descriptors ...string) bool {
	isSeekerRelated := false
	for _, descriptor := range descriptors {
		containsSeeker, _ := regexp.MatchString(".*[sS][eE][eE][kK][eE][rR].*", descriptor)
		isSeekerRelated = isSeekerRelated || containsSeeker
	}
	return isSeekerRelated
}

type SeekerDownloader struct {
}

func (d SeekerDownloader) DownloadFile(url, destFile string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("could not download: " + strconv.Itoa(resp.StatusCode))
	}
	return d.writeToFile(resp.Body, destFile, 0666)
}

func (d SeekerDownloader) writeToFile(source io.Reader, destFile string, mode os.FileMode) error {
	err := os.MkdirAll(filepath.Dir(destFile), 0755)
	if err != nil {
		return err
	}

	fh, err := os.OpenFile(destFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer fh.Close()

	_, err = io.Copy(fh, source)
	if err != nil {
		return err
	}
	return nil
}

type SeekerUnzipper struct {
}

func (s SeekerUnzipper) Unzip(zipFile, destFolder string) error {
	return libbuildpack.ExtractZip(zipFile, destFolder)
}
