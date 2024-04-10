// Package experimental provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/algorand/oapi-codegen DO NOT EDIT.
package experimental

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	. "github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/oapi-codegen/pkg/runtime"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Get a list of assets held by an account, inclusive of asset params.
	// (GET /v2/accounts/{address}/assets)
	AccountAssetsInformation(ctx echo.Context, address string, params AccountAssetsInformationParams) error
	// Returns OK if experimental API is enabled.
	// (GET /v2/experimental)
	ExperimentalCheck(ctx echo.Context) error
	// Fast track for broadcasting a raw transaction or transaction group to the network through the tx handler without performing most of the checks and reporting detailed errors. Should be only used for development and performance testing.
	// (POST /v2/transactions/async)
	RawTransactionAsync(ctx echo.Context) error
}

// ServerInterfaceWrapper converts echo contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler ServerInterface
}

// AccountAssetsInformation converts echo context to params.
func (w *ServerInterfaceWrapper) AccountAssetsInformation(ctx echo.Context) error {
	var err error
	// ------------- Path parameter "address" -------------
	var address string

	err = runtime.BindStyledParameterWithLocation("simple", false, "address", runtime.ParamLocationPath, ctx.Param("address"), &address)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter address: %s", err))
	}

	ctx.Set(Api_keyScopes, []string{""})

	// Parameter object where we will unmarshal all parameters from the context
	var params AccountAssetsInformationParams
	// ------------- Optional query parameter "limit" -------------

	err = runtime.BindQueryParameter("form", true, false, "limit", ctx.QueryParams(), &params.Limit)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter limit: %s", err))
	}

	// ------------- Optional query parameter "next" -------------

	err = runtime.BindQueryParameter("form", true, false, "next", ctx.QueryParams(), &params.Next)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid format for parameter next: %s", err))
	}

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.AccountAssetsInformation(ctx, address, params)
	return err
}

// ExperimentalCheck converts echo context to params.
func (w *ServerInterfaceWrapper) ExperimentalCheck(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.ExperimentalCheck(ctx)
	return err
}

// RawTransactionAsync converts echo context to params.
func (w *ServerInterfaceWrapper) RawTransactionAsync(ctx echo.Context) error {
	var err error

	ctx.Set(Api_keyScopes, []string{""})

	// Invoke the callback with all the unmarshalled arguments
	err = w.Handler.RawTransactionAsync(ctx)
	return err
}

// This is a simple interface which specifies echo.Route addition functions which
// are present on both echo.Echo and echo.Group, since we want to allow using
// either of them for path registration
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
}

// RegisterHandlers adds each server route to the EchoRouter.
func RegisterHandlers(router EchoRouter, si ServerInterface, m ...echo.MiddlewareFunc) {
	RegisterHandlersWithBaseURL(router, si, "", m...)
}

// Registers handlers, and prepends BaseURL to the paths, so that the paths
// can be served under a prefix.
func RegisterHandlersWithBaseURL(router EchoRouter, si ServerInterface, baseURL string, m ...echo.MiddlewareFunc) {

	wrapper := ServerInterfaceWrapper{
		Handler: si,
	}

	router.GET(baseURL+"/v2/accounts/:address/assets", wrapper.AccountAssetsInformation, m...)
	router.GET(baseURL+"/v2/experimental", wrapper.ExperimentalCheck, m...)
	router.POST(baseURL+"/v2/transactions/async", wrapper.RawTransactionAsync, m...)

}

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
