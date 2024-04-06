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

	"H4sIAAAAAAAC/+x9/XPcNrLgv4Ka96r8cUPJn9m1r7beKXaS1cVOXJaSvfcsX4Ihe2aw4gBcABzNxOf/",
	"/QoNgARJYIYjKXJS9X6yNSSBRqPR6O/+NMnFqhIcuFaTl58mFZV0BRok/kXzXNRcZ6wwfxWgcskqzQSf",
	"vPTPiNKS8cVkOmHm14rq5WQ64XQF7Tvm++lEwr9qJqGYvNSyhulE5UtYUTOw3lbm7WakTbYQmRvixA5x",
	"+nryeccDWhQSlBpC+SMvt4TxvKwLIFpSrmhuHilyxfSS6CVTxH1MGCeCAxFzopedl8mcQVmoI7/If9Ug",
	"t8Eq3eTpJX1uQcykKGEI5yuxmjEOHipogGo2hGhBCpjjS0uqiZnBwOpf1IIooDJfkrmQe0C1QITwAq9X",
	"k5cfJgp4ARJ3Kwe2xv/OJcBvkGkqF6AnH6exxc01yEyzVWRppw77ElRdakXwXVzjgq2BE/PVEXlbK01m",
	"QCgn7799RZ4+ffrCLGRFtYbCEVlyVe3s4Zrs55OXk4Jq8I+HtEbLhZCUF1nz/vtvX+H8Z26BY9+iSkH8",
	"sJyYJ+T0dWoB/sMICTGuYYH70KF+80XkULQ/z2AuJIzcE/vyrW5KOP8X3ZWc6nxZCcZ1ZF8IPiX2cZSH",
	"BZ/v4mENAJ33K4MpaQb98Ch78fHT4+njR5//7cNJ9l/uz+dPP49c/qtm3D0YiL6Y11ICz7fZQgLF07Kk",
	"fIiP944e1FLUZUGWdI2bT1fI6t23xHxrWeealrWhE5ZLcVIuhCLUkVEBc1qXmviJSc1Lw6bMaI7aCVOk",
	"kmLNCiimhvteLVm+JDlVdgh8j1yxsjQ0WCsoUrQWX92Ow/Q5RImB61r4wAX9cZHRrmsPJmCD3CDLS6Eg",
	"02LP9eRvHMoLEl4o7V2lDrusyPkSCE5uHtjLFnHHDU2X5ZZo3NeCUEUo8VfTlLA52YqaXOHmlOwSv3er",
	"MVhbEYM03JzOPWoObwp9A2REkDcTogTKEXn+3A1RxudsUUtQ5GoJeunuPAmqElwBEbN/Qq7Ntv/vsx9/",
	"IEKSt6AUXcA7ml8S4LkooDgip3PChQ5Iw9ES4tB8mVqHgyt2yf9TCUMTK7WoaH4Zv9FLtmKRVb2lG7aq",
	"V4TXqxlIs6X+CtGCSNC15CmA7Ih7SHFFN8NJz2XNc9z/dtqOLGeojamqpFtE2Ipu/vZo6sBRhJYlqYAX",
	"jC+I3vCkHGfm3g9eJkXNixFijjZ7GlysqoKczRkUpBllByRumn3wMH4YPK3wFYDjB0mC08yyBxwOmwjN",
	"mNNtnpCKLiAgmSPyk2Nu+FSLS+ANoZPZFh9VEtZM1Kr5KAEjTr1bAudCQ1ZJmLMIjZ05dBgGY99xHHjl",
	"ZKBccE0Zh8IwZwRaaLDMKglTMOFufWd4i8+ogq+epe749unI3Z+L/q7v3PFRu40vZfZIRq5O89Qd2Lhk",
	"1fl+hH4Yzq3YIrM/DzaSLc7NbTNnJd5E/zT759FQK2QCHUT4u0mxBae6lvDygj80f5GMnGnKCyoL88vK",
	"/vS2LjU7YwvzU2l/eiMWLD9jiwQyG1ijChd+trL/mPHi7FhvonrFGyEu6ypcUN5RXGdbcvo6tcl2zEMJ",
	"86TRdkPF43zjlZFDv9CbZiMTQCZxV1Hz4iVsJRhoaT7HfzZzpCc6l7+Zf6qqNF/rah5DraFjdyWj+cCZ",
	"FU6qqmQ5NUh87x6bp4YJgFUkaPvGMV6oLz8FIFZSVCA1s4PSqspKkdMyU5pqHOnfJcwnLyf/dtzaX47t",
	"5+o4mPyN+eoMPzIiqxWDMlpVB4zxzog+agezMAwaHyGbsGwPhSbG7SYaUmKGBZewplwftSpLhx80B/iD",
	"m6nFt5V2LL57KlgS4cS+OANlJWD74j1FAtQTRCtBtKJAuijFrPnh/klVtRjE5ydVZfGB0iMwFMxgw5RW",
	"D3D5tD1J4Tynr4/Id+HYKIoLXm7N5WBFDXM3zN2t5W6xxrbk1tCOeE8R3E4hj8zWeDQYMf82KA7ViqUo",
	"jdSzl1bMy39374ZkZn4f9fGfg8RC3KaJCxUthzmr4+AvgXJzv0c5Q8Jx5p4jctL/9npkY0bZQTDqtMXi",
	"bRMP/sI0rNReSgggCqjJbQ+Vkm4nTkjMUNgbkslPCiyFVHTBOEI7NeoTJyt6afdDIN4NIYBq9CJLS1aC",
	"bEyoTuZ0qD8a2Fn+BNTq0KgaqnVSqJFSS6Y06tRIAWQJJQrNlHtiDsnkWlQxYrN3LKCB+UrSytKxe2JF",
	"LsZRl7cvWVhveOmOvA+jMAesPthkhOraLHkv24xCghyjB8PXpcgv/07V8hZO98yPNaR7nIYsgRYgyZKq",
	"ZeTQ9Oi6HW0MbZsXkWbJLJjqqFnibS1vz9IKqmmwNAdvXHq1qMfv8G4EGVFxf8T/0JKYx+YKMBKCHfaI",
	"nCPnUJbrO19UYbmaORR2JvMCGqsEWVk7EKlofnkQlK/ayeP7NGqPvrGmJ7dDbhHNDp1vWKFua5twsNRe",
	"hXrM6Wur+PtraMDIu5dMbO12rjEIOBcVKWENZR8Ey7JwNIsQsbl1vvC12MRg+lpsBjxBbOBWdsKMM/qS",
	"/1psXjvIhNyPeRx7DNLNAo3Kp5A98FBSNrO0To2TmZDXY8c9PstJ66oh1Iwa3EbTHpLw1brK3NmMmHvt",
	"C72BWu/4bi7aHz6GsQ4WzjT9HbCgzKi3gYXuQLeNBbGqWAm3QPrL6C04owqePiFnfz95/vjJL0+ef2VI",
	"spJiIemKzLYaFLnvbBpE6W0JD6KiJZqc4qN/9cwb+LvjxsZRopY5rGg1HMo6DqzqYF8j5r0h1rpoxlU3",
	"AI7iiGCuNot2Yn1iBrTXTBnhczW7lc1IIaxoZymIg6SAvcR06PLaabbhEuVW1rehU4GUQkavrkoKLXJR",
	"ZmuQiomIVvTOvUHcG14trPq/W2jJFVXEzI0uk5oXCeVHb/h4vm+HPt/wFjc7Ob9db2R1bt4x+9JFfqv7",
	"VCAzveGkgFm96OhkcylWhJICP8Q7+jvQVm5hKzjTdFX9OJ/fjolF4EAR5ZGtQJmZiH3DSA0KcsFtBNEe",
	"PdGNOgY9fcR407ZOA+AwcrblOdrnb+PYplXoFePoLFRbngf6tIGxhGLRIcub680pdNip7qkIOAYdb/Ax",
	"GghfQ6npt0Ket2Lfd1LU1a0Lef05xy6HusU4E2RhvvW2J8YXZTdqbWFgP4qt8Yss6JU/vm4NCD1S5Bu2",
	"WOpAz3onhZjfPoyxWWKA4gOrpZbmm6Gu+oMoDDPRtboFEawdrOVwhm5DvkZnotaEEi4KwM2vVVw4S8Q5",
	"YYAFxoXoUN7TS6t4zsBQV05rs9q6Ihj1MLgv2g8zmtsTmiFqVMLn2zjr7Vt2OhtDU0qgxZbMADgRM+dY",
	"dS5fXCTFkA3txRsnGkb4RQeuSooclIIiczawvaD59+zVoXfgCQFHgJtZiBJkTuWNgb1c74XzErYZBhgp",
	"cv/7n9WDLwCvFpqWexCL78TQ29g9nPd8CPW46XcRXH/ykOyoBOLvFaIFSrMlaEih8CCcJPevD9FgF2+O",
	"ljVI9GP/rhTvJ7kZATWg/s70flNo6yoRNuvUWyPhmQ3jlAsvWMUGK6nS2T62bF7q6OBmBQEnjHFiHDgh",
	"eL2hStvYC8YLtAXa6wTnsUKYmSINcFINMSP/7DWQ4di5uQe5qlWjjqi6qoTUUMTWgG6g5Fw/wKaZS8yD",
	"sRudRwtSK9g3cgpLwfgOWXYlFkFUN04f50YaLg4deeae30ZR2QGiRcQuQM78WwF2w9DBBCBMtYi2hMNU",
	"j3KaeMXpRGlRVYZb6KzmzXcpNJ3Zt0/0T+27Q+Kiur23CwEKIxbd+w7yK4tZGzS6pIo4OLxfD80gNkhk",
	"CLM5jJliPIdsF+WjimfeCo/A3kNaVwtJC8gKKOk24pG0j4l9vGsA3PFW3RUaMhv9F9/0lpJ9sNWOoQWO",
	"p2LCI8EnJDdH0KgCLYG4r/eMXACOHWNOjo7uNUPhXNEt8uPhsu1WR0bE23AttNlxRw8IsuPoYwBO4KEZ",
	"+vqowI+zVvfsT/GfoNwEjRxx+CRbUKkltOMftICEDdUlVgTnpcfeexw4yjaTbGwPH0kd2YRB9x2VmuWs",
	"Ql3ne9jeuurXnyDqdyUFaMpKKEjwwKqBVfg9sXFr/TGvpwqOsr0NwR8Y3yLL8fEBXeAvYYs69zsbEB2Y",
	"Om5Dl42Mau4nygkC6sMsjQgevgIbmutyawQ1vYQtuQIJRNWzFdPaJjp0VV0tqiwcIOrX2DGj82pGfYo7",
	"3axnOFSwvFiAi9UJdsN33lMMOuhwukAlRDnCQjZARhSCUZEnpBJm15nLufBR956SOkA6po0u7eb6v6c6",
	"aMYVkP8UNckpR5Wr1tDINEKioIACpJnBiGDNnC4iqsUQlLACq0nik4cP+wt/+NDtOVNkDlc+Ucm82EfH",
	"w4dox3knlO4crluwh5rjdhq5PtDhYy4+p4X0ecr+UAs38pidfNcbvPESmTOllCNcs/wbM4DeydyMWXtI",
	"I+PCTHDcUb6cjst+uG7c9zO2qkuqb8NrBWtaZmINUrIC9nJyNzET/Js1LX9sPsMkLMgNjeaQ5Zg6NHIs",
	"ODff2GwjMw7jzBxgG2k8FiA4tV+d2Y/2qJhteBxbraBgVEO5JZWEHGySjZEcVbPUI2LDb/Ml5QtUGKSo",
	"Fy6izo6DDL9W1jQjaz4YIipU6Q3P0MgduwBczL/PszLiFFCj0vUt5FaBuaLNfC61bszNHOxB32MQdZJN",
	"J0mN1yB13Wq8FjndZLERl0FH3gvw00480pWCqDOyzxBf4baYw2Q29/cx2bdDx6AcThyEGrYPU9GGRt0u",
	"t7cg9NiBiIRKgsIrKjRTKftUzMPEUHeHqa3SsBpa8u2nvySO3/ukvih4yThkK8FhG62FwDi8xYfR44TX",
	"ZOJjFFhS3/Z1kA78PbC684yhxpviF3e7f0L7Hiv1rZC35RK1A44W70d4IPe6292U1/WT0rKMuBZd2lif",
	"AahpE2PNJKFKiZyhzHZaqKk9aM4b6XLMuuh/1wTD38LZ64/b86GFGcloI4ayIpTkJUMLsuBKyzrXF5yi",
	"jSpYaiT4ySvjaavlK/9K3EwasWK6oS44xcC3xnIVDdiYQ8RM8y2AN16qerEApXu6zhzggru3GCc1Zxrn",
	"WpnjktnzUoHECKQj++aKbsnc0IQW5DeQgsxq3ZX+MStSaVaWzqFnpiFifsGpJiVQpclbxs83OJx3+vsj",
	"y0FfCXnZYCF+uy+Ag2IqiwdpfWefYkCxW/7SBRdjFQv72AdrtmnaE7PMTmWG/3v/P15+OMn+i2a/Pcpe",
	"/I/jj5+efX7wcPDjk89/+9v/6/709PPfHvzHv8d2ysMey9lzkJ++dprx6WtUf1of0AD2O7P/rxjPokQW",
	"RnP0aIvcx/x0R0APusYxvYQLrjfcENKalqwwvOU65NC/YQZn0Z6OHtV0NqJnDPNrPVCpuAGXIREm02ON",
	"15aihnGN8exYdEq6hFc8L/Oa26300rdN/vLxZWI+bTKgbXGklwTTY5fUB0e6P588/2oybdNam+eT6cQ9",
	"/RihZFZsYsnLBWxiuqI7IHgw7ilS0a0CHeceCHs0lM7GdoTDrmA1A6mWrLp7TqE0m8U5nM+VcDanDT/l",
	"NjDenB90cW6d50TM7x5uLQEKqPQyVjSlI6jhW+1uAvTCTiop1sCnhB3BUd/mUxh90QX1lUDnWLwDtU8x",
	"RhtqzoElNE8VAdbDhYwyrMTop5cW4C5/devqkBs4Bld/zsaf6f/Wgtz77ptzcuwYprpn8+jt0EHmc0SV",
	"dllbnYAkw81sqSgr5F3wC/4a5mh9EPzlBS+opsczqliujmsF8mtaUp7D0UKQlz4R7DXV9IIPJK1kNbcg",
	"U5NU9axkObkMFZKWPG2FnuEIFxcfaLkQFxcfB7EZQ/XBTRXlL3aCzAjCotaZqy+SSbiiMub7Uk19CRzZ",
	"FhDaNasVskVtDaS+fokbP87zaFWpfp75cPlVVZrlB2SoXBa12TKitJBeFjECisslNPv7g3AXg6RX3q5S",
	"K1Dk1xWtPjCuP5Lson706CmQTuL1r+7KNzS5rWC0dSWZB983quDCrVoJGy1pVtFFzMV2cfFBA61w91Fe",
	"XqGNoywJftZJ+PaB+ThUu4AmtzK5ARaOg7MScXFn9itfSy6+BHyEW9jN/LzRfgXZptferj2Jv7TWy8yc",
	"7eiqlCFxvzNNiamFEbJ8NIZiC9RWXTWuGZB8CfmlK5MEq0pvp53PfcCPEzQ962DKFtCymXlYwgUdFDMg",
	"dVVQJ4pTvu3X0lCgtQ8rfg+XsD0XbQWYQ4pndGs5qNRBRUoNpEtDrOGxdWP0N99FlaFiX1W+JAImPXqy",
	"eNnQhf8mfZCtyHsLhzhGFJ1aAylEUBlBhCX+BAqusVAz3o1IP7Y8o2XM7M0XKableT9xr7TKkwsAC1eD",
	"Vnf7fAVYjU9cKTKjRm4XrpCcrVcQcLFa0QUkJOTQRzQy3bvjV8JB9t170ZtOzPsX2uC+iYJsX87MmqOU",
	"AuaJIRVUZnphf34m64Z0ngmsD+sQNitRTGriIy3TobLjq7MFL1OgxQkYJG8FDg9GFyOhZLOkyte4w1KA",
	"/iyPkgF+x4oGu6ounQYRa0G9v6amkue5/XM60C5d7SVfcMlXWQpVyxEVk4yEj0Hyse0QHAWgAkpY2IXb",
	"lz2htLVA2g0ycPw4n5eMA8liwW+BGTS4ZtwcYOTjh4RYCzwZPUKMjAOw0b2OA5MfRHg2+eIQILmrZUL9",
	"2OiYD/6GePqYDQc3Io+oDAtnCa9W7jkAdRGTzf3Vi9vFYQjjU2LY3JqWhs05ja8dZFD8B8XWXqkfF+Dx",
	"ICXO7nCA2IvloDXZq+g6qwllJg90XKDbAfFMbDKbPxqVeGebmaH3aIQ8ZrPGDqYts3RPkZnYYNAQXi02",
	"InsPLGk4PBiBhr9hCukVv0vd5haYXdPulqZiVKiQZJw5ryGXlDgxZuqEBJMil/tB5aRrAdAzdrRlyJ3y",
	"u1dJ7Yonw8u8vdWmbUVAn3wUO/6pIxTdpQT+hlaYaawkTtJM0TlRd1LkaWi/uEnxLftxZQtqHVJ7q08O",
	"HSB2YPVdXw6MorUbUdTFa4C1GCsxzHfo+hqiTUEJqGplHdE0u4z5o43GCHiPn/nPApMQ7h7l2wdBmJqE",
	"BVMaWteEjz75EkZfipVBhZinV6crOTfrey9Ec/lb5yx+2Fnmna8A47znTCqdoV8nugTz0rcKTRXfmlfj",
	"Emg3EM7W0WZFnOPitJewzQpW1nF6dfN+/9pM+0Nz0ah6hrcY4zYMaIZ136PhsTumthHUOxf8xi74Db21",
	"9Y47DeZVM7E05NKd409yLnoMbBc7iBBgjDiGu5ZE6Q4GGaQ1D7ljII0GkRNHu2zag8NU+LH3xkL55OrU",
	"zW9Hiq4lMMPsXAVD55u5EpkOyqYP840TZ4BWFSs2PQuzHTVph6AHmZESFx7urhtsDwa60Y7R4PFOoU4X",
	"U+ksaceodhwbwdgGWboIQpAoYthM26KWaKrshDAOq8I24vLItX//85kWki7AmZszC9KNhsDlHIKGoOaq",
	"IppZv3HB5nMIzazqOibCDnB9Y1q0s8oIIovbYmvG9VfPYmS0h3paGPejLE4xEVpIOd/Oh+ZsL1YF2nxT",
	"8zLYmmvYpKN5ud/DNvvZ6H2kokyqNg7P2Ze7/O+AXV+vvoctjrw3vM0AtmdXUPl/D0iDMWNr80gFJTLv",
	"qU4BYZTwO1t4wE6dxHfplrbGlXxOE38b7N4pidxdyk0ORusNNbCM2Y2zuBPSnB7oIr5Pyvs2gSVMnCE5",
	"BiJXOBVTvkHW8Cpqks730e450NITLy5n8nk6uZnLL3abuRH34Ppdc4FG8YwhZdYF1PHgH4hyWlVSrGmZ",
	"Ocdo6vKXYu0uf3zd+1HvWJiMU/b5Nydv3jnwP08neQlUZo0yllwVvlf9aVZli0TvvkpQYvG2JqusB5vf",
	"lCwNnalXS3CdTAJ9f1ByvXWUB0fROVfn8cjWvbzP+fTtEnf49qFqXPut28l69rvefLqmrPT+Hg9tIgoV",
	"Fzeubn+UK4QD3DgqIAjuyG6V3QxOd/x0tNS1hyfhXD9iDbq4xsFdhTpkRc7LT29devpWyA7zdylI0SiB",
	"30+sMkK2xWMiKNN3x+oLU0fECl6/Ln41p/Hhw/CoPXw4Jb+W7kEAIP4+c7+jfvHwYdSBE7UkGCaBhgJO",
	"V/CgCadObsTdmp04XI27oE/Wq0ayFGkybCjUuvs9uq8c9q4kc/gs3C8FlGB+2p+x2Nt0i+4QmDEn6CyV",
	"ctREk61sQy5FBO8HT2K2myEtZPYrii0HrD9seIR4vUIfUqZKlse963ymDHvlNmrKvEzw5YTBzIxYs0QQ",
	"Hq9ZMJZ5bUxxxB6QwRxRZKpofcYWdzPhjnfN2b9qIKwwWs2cgcR7rXfVeeUARx0IpEb1HM7lBraugnb4",
	"m9hBdpj8LRC7jSA7XSivG7O+X2isrcCBoZ7hjAPGvSNM09GHo2abtrLsxlqN02PGNGb1jM75SxJzRBut",
	"MpXNpfgN4rZoNOFHMt6974lhfPNvEKpnYXvBDktp/Hptv9h29n3bPV43Tm38jXVhv+imp8l1LtP4qT5s",
	"I6+j9Kp4XVaH5JQSFjp5uzHACdaCxyuIesM+AT4AhHJ7nmy6dyeVJH4qw6StYzt+eyodzINEt5JezWis",
	"iYLRhQxMwfZ2QlW0IP5jvwGqSWa2s5MgVLN5l9mSURXItuLHsPzkNfUaO+1ojaZVYJCiQtVlaj3FpRKR",
	"YWp+RbntUWq+s/zKfa3AekHNV1dCYsE3FY+qKSBnq6g59uLiQ5EPIygKtmC2/WatIOjv6AayrY0tFbke",
	"mU2KvkPN6Zw8mgZNZt1uFGzNFJuVgG88tm/MqMLrsvFINp+Y5QHXS4WvPxnx+rLmhYRCL5VFrBKk0T1R",
	"yGtiw2agrwA4eYTvPX5B7mNUnGJreGCw6ISgycvHLzCmwf7xKHbLuvapu1h2gTz7H45nx+kYwwLtGIZJ",
	"ulGPorWxbP/09O2w4zTZT8ecJXzTXSj7z9KKcrqAeCD2ag9M9lvcTfSo9vDCrTcAlJZiS5iOzw+aGv6U",
	"SO407M+CQXKxWjG9crFTSqwMPbXNG+2kfjjbSdg1VPFw+YcYglj5CKyereuO1Ri6SiRnYKDoD3QFXbRO",
	"CbVV/krWBgf7bmDk1BcRxQ4zTWMZixszl1k6ypIYKzwnlWRco/2j1vPsr0YtljQ37O8oBW42++pZpFNL",
	"t5kBPwzwO8e7BAVyHUe9TJC9l1nct+Q+FzxbGY5SPGiTqYNTmYyVjEfFpULzdg89VvI1o2RJcqs75EYD",
	"Tn0jwuM7BrwhKTbrOYgeD17ZnVNmLePkQWuzQz+9f+OkjJWQscrg7XF3EocELRmsMTUmvklmzBvuhSxH",
	"7cJNoP+yIShe5AzEMn+Wo4pA4NHclRVrpPif37YljtGxalOOejZAISPWTme3u+OAr8Osbn3/rY3ZwWcJ",
	"zI1GG44yxEoiANpGODff3HGSdNTca/e8Y3B8/CuRRgdHOf7hQwT64cOpE4N/fdJ9bNn7w4fxSqNRk5v5",
	"tcXCTTRi/Da2h1+LiAHMt/VqAopcInTEAJm6pMwDwwRnbqgp6bZQunsp4nZSbOIBf/FTcHHxAZ94POAf",
	"fUR8YWaJG9gGiqcPe7eFXJRkiuZ5EGpMyddiM5ZweneQJ54/AIoSKBlpnsOVDFrkRd31e+NFAho1o86g",
	"FEbJDLt/hPb8Pw+ezeKnO7Bds7L4uS3i1LtIJOX5MhqoOTMf/mJl9M4VbFlltKHAknIOZXQ4q9v+4nXg",
	"iJb+TzF2nhXjI9/tt2i0y+0trgW8C6YHyk9o0Mt0aSYIsdqtj9PkX5cLURCcp61e3zLHYa/ToAEbtnuO",
	"HQ3bBxoVfHR2GeZr+38R4AVav47Id1ipwsDSKU2MVidf9LFbAK2uSkGLKRajPP/m5A2xs9pvbN9u239s",
	"gUaX7iqiVvKDG2mnKh2MH2d36rVZtdJZ0y4sVkvKvNE2NGO90Ak0x4TYOSKvrSVMeTuLnYRgSVO5giLo",
	"TmZ1MaQJ8x+tab5EE1PnIkuT/PjGeZ4qWwN8kMfTdKvAc2fgdr3zbOu8KcGO41dMAea2whq65auaWm7O",
	"xOnLWXWXJ2vOLaUc0oi86U1xKNo9cFYg8b7hKGQ9xB9oYLB9Jw/tI3iGX0WLZ/ebEvact74YUtNd+a2z",
	"EeeUC85yLF0dE4iw1M44b9OIKt9xN5GauBMaOVzRVohNVp3DYrI5omeEDnFDz23w1GyqpQ77p4aNa5Gz",
	"AK0cZ4Ni6jt6Or8G4wpc9xFDRCGfFDISmxKNZ2/84AeSEVbRSBiqvjXPfnBmTEwvv2QcDRYObU7Mtp6H",
	"UjF0MHLCNFkIUG493VJi6oP55girahWw+Xj0RixYfsYWOIaNhjLLtqF/w6FOfCCgC7wz774y77pax83P",
	"nageO+lJVblJ0/1e402uNzyJ4Fj4iY8HCJDbjB+OtoPcdkbw4n1qCA3WGHwEFd7DA8Joep/2Go0bFcFS",
	"FL5BbG5StOAh4xEw3jDuPWHxCyKPXgm4MXheE9+pXFJtRcBRPO0caJmIY8dcP+tKvelQ/UrPBiW4Rj9H",
	"ehvbtq0JxtG80ApulG+JPxSGugNh4hUtmwjYSBNWlKqcEFVgjkivLWuMcRjG7Rs/dy+APb3ep+3nWD39",
	"0JsoVVNqVhcL0BktilgzmK/xKcGnPtcHNpDXTdOQqiI5llDt1pQdUpubKBdc1asdc/kXbjhd0Oc4Qg1h",
	"r2W/w1izYrbFfw/pwt/Evh6c3+YDXYvDCikP8/ViUq+h6UyxRTYeE3in3Bwd7dTXI/T2+1ul9FIsuoB8",
	"CSNpgsuFexTjb9+YiyMstDgIM7ZXS1MHEUN6BT73pUOaCl5droRX2aAvDDqvm+73u80Q6T72U7z8Ejml",
	"ocnb3q/WDJzKLM2TidBUu0I3mpKdLChZPMSGfPaM6ENPUCrM00Z53p7x2a11J0LTLpjvOw4XG+rTMouk",
	"o+V6vpB2gw91hny/TiUb+7rq+Lzf5/oSXPW7SsKaidoH0fhQVq8S2l87XaObdO/o+qMB4l/a+Jw0lZ+7",
	"foN2mU4n//5n60wjwLXc/gEM54NNH3TQHkq71jzVvkKaVlWjWld1bsUxPQdi5e2dbNjp4b2nA/mArF6P",
	"EQeGHcWnk9PioAsz1iJhYkeJHbt4f/B0Bem2ajQesUoo1naMizUOHxkzfo69v4MK2MOxfCzhGnKNbQLb",
	"GCkJcEg9bDOZt93/dyXptDrdhNa7AtK7qkYPewPuueMHJUiCMjq2r9rR+BrJJ00krE3kuaIKOwpItHF3",
	"U19HJ+DN55Brtt5T8uUfS+BBOZGpt8sgLPOgAgxr0lGwDuvhVscWoF0VWXbCE/RDuDE4qXTkS9jeU6RD",
	"DdFGb00u1nVKcCIGkDtkhkSEikWaWUOyC/5hqqEMxIKP7LSfQ1vMPNkjOihgdM25PEmai6MtarRjyniT",
	"2lFzmU8PKqCGmRWpqjDDHpdp/eM1thRVLs6JNiU8Qy2dnA4bHVy5EqBYoKfxnfhioKD8b74al52lZJcQ",
	"drFGT9UVlYV/I2p68VadbMd9NCjl4vsz9oGeNzOzNg5/6KuOlM7GlJa8FEaMyFJ5Qd3Q9yZu7J6yAX5t",
	"HRaEaw7SdftH+bcUCjItfNz+Ljh2ocJGMV4LCSrZrsIClywi+76tkotteygWjaUueDFcIJGwogY6GdSy",
	"Tc+5C9mv7HOfS+3btuy1MDX0ur9/oM/AYGqAxJDq58TdlvtztK9jbGKcg8y856lf2JaD7HpDKimKOrcX",
	"dHgwGoPc6BIoO1hJ1E6TD1fZ0xGCXOdL2B5bJcg3XvQ7GAJtJScLelC6r7fJt2p+UzG4F7cC3pe0XE0n",
	"lRBllnB2nA6r8fYp/pLll1AQc1P4SOVET11yH23sjTf7arn11WerCjgUD44IOeE2N8Q7trvtoHqT83t6",
	"1/wbnLWobYFsZ1Q7uuDxIHssXS1vyM38MLt5mALD6m44lR1kT63XTaISsKRXkQ7TR2O18qGrud/1tyUq",
	"C0VMJjmzHqtXeNBjhiPMZA9KLqAjkxLn6SKqFLGQzOtk25uh4pgKJ0OANPAxSd8NFG7wKAKifWwjp9BW",
	"MHO1y8ScSGidyNct4jZsuRvT6PszN7N0+d1cSOg0zzVfC1l4kYeptss1lTOmJZXb65RaG7T8HVhPklje",
	"G47VRGK1C2mjsYY4LEtxlSGzypqK8THV1rynupexb5LTfmdO9QyCuC6qnKC2JUtakFxICXn4RTxtz0K1",
	"EhKyUmCYV8wDPddG7l5hrg4npVgQUeWiANt5IU5BqblqzimKTRBE1URRYGkHkz7tNwEdj5zytvpN2+I8",
	"dtGZ9WUmAk9BuWI8DkP25SG8O3o1H9Tz4HSOFiGGsS7d3GsrfYYdq+HAhtWsLL3BINWzmvykagxHwsQb",
	"M8UzshJKO83OjqSaodoQr/u54FqKsuwagaxIvHCW7bd0c5Ln+o0QlzOaXz5APZIL3ay0mPq01H4wXjuT",
	"7FVkGtlc+3wZsfPiLP7UHdxB23GOgxvfBmB+3M+x9tu4T2INwrvr6ne854namVqsWB6n4T9XdFsyJi3G",
	"EqKlnmzvKZucj68how4vhyaYAVnSEM3ADcHG9svxNOfUReZh/osSb39cMgd3SSQupiGfdFJLlidlqx4A",
	"CKnNGNW1tA2rQsmn4SpiYTPM0SXdB3QkF8fIn5vBZka4daA03AioQbRhA+B9q+xPbUkuG7k4Exv//EFb",
	"s+tawH/eTeWxJv+RU9yQlrRBVb6+R4IjxCsD74w/wnbs/gbdH4XUNBcceaMGAKTjkjowjIpOOhSMOWUl",
	"FBnVicsdbULTQLN1GS39lrFMOU6eU3thL4GYsWsJrt6EFal7LeYrakhJNK8PLbe8gA0oLAZh+2RTZf0M",
	"3t8BpW3W1VO+RZWVsIZOuJYrglGjaMfW4L9VzcekAKjQ+9e3ScXikMK7vGeocGvPgkiWMdiNWi4sYu1O",
	"kT1miagRZcMze0zU2KNkIFqzoqYd/KlDRY6u2c0c5QiqBjJ55vW2sdP8ZEd47wc48d/HRBmPiY/j+NDB",
	"LCiOul0MaG9cYq1Sp57HwxLDCi+NQwNnKxrHpyXxlm+oil7xtAFwSPKtejNyn5jgAWK/2UCOUk037u7m",
	"OCE4GFG96k1JEVw2O3x9Q/IXoeGdJJwcL6ZqKEAGu9NS4+nCCez4AjYJ5UbsNVIzNuZy/N/xvymZ1X4g",
	"o1fbPmGhBvcavMcOC0o3zgon0LLmQvPxhVNXT7CvlLMgsnpFt0RI/Mfoa/+qacnmWzyhFnz/GVFLakjI",
	"uQit79rFK5qJdwsmUw+YtwsIP5VdNxs7ZjDc1owSAG2uQGecwspAlxBuA7rlLefJtWE5qp6tmFJ42fW2",
	"c4gFt3hfE2JFi1BHxsp03Qatvlap+fp/tllb4VS+oFRV0tx3hQOi6KpnELedHz1x6SWsdqf1DdVjTwJN",
	"N8mWaKVP5y2uYdw7MHIjFiuf6vfQAXvQZW/Q6uJGyzik7XObGb0jIXLUUm57F8bGhwyADntz7QM/bFV2",
	"N/iPFo1MLWMM+H8UvCeaE4bw2j6Ed4DlTsp/BFZrV52JTSZhrvaFQljDqlGEZVsswBsnGc8lUGVjQ05/",
	"dCpbWxORcaNC2ujFxvvWjFLAnPGWWTJe1TqiAWBpRL4NEBaapxGtCWdPSkowYtialj+uQUpWpDbOnA7b",
	"xiusSe9N8u7biPLf3KnDAZhqtR/MJIQ2Uy14zVzgtuuNDSxUmvKCyiJ8nXGSgzT3PrmiW3V934eBVtZG",
	"vtjj/aCBNNPNbw/8IEjaFpBy69yXN/RMNADSW3RRjHAtYARrxK1gjSJaJDwJQxjiZRXoJivFAvPLEgTo",
	"ik+i78cqK4KjwdbKQ4fNo9hvsHsarLvtDr4WOOuYKXafsx8Rdajw/MSZ3nnSrDWtn/BnIzLtQfD0zxdt",
	"WLjdnCH9x3I0zzGJoZOn2W/l7/fahofY+SDhyehacBO7iA5yl+AbmmvH9zPq+uBjmaBWh81Qt1U7Ar9B",
	"tUHONHeBO0Ojz0AptkiZujzaA21C1pLs74EEeLb/rztb3WmbYAozziFNoHZnzmaVqLJ8TDSgLc1fOIO2",
	"g7QLY4I+AnN1Yt1N4IRqmlV0Cpt0ulYc2gcr2TVjn1+myncp2SmDRoKDdo3lYo68zHbHRTsM5ng0xotp",
	"P/uoa7BpmAShREJeSzRoXtHt/r5CiZKwZ38/ef74yS9Pnn9FzAukYAtQbVnhXl+eNmKM8b6d5W5jxAbL",
	"0/FN8HnpFnHeU+bTbZpNcWfNclvV1gwcdCU6xBIauQAixzHSD+Zae4XjtEHff6ztii3y1ncshoLff8+k",
	"KMt4WfdGdIuY+mO7FRj7jcRfgVRMacMIu746pttYWbVEcxwW91zbOiOC5676ekMFTCeCcWILSYVaIj/D",
	"rF/n3yCwqUrHq6xPYte6nF5kLWIYnIHxGzMglaicKM3mJAYR5pbIIOfSGRoxvDOInmyYrY2jjBGii0mO",
	"k94Jd5qnmJPd3L7brVHHOb3ZxIh44Q/lNUgzZUlPZ7Rfh5O0pvQ/DP+IpOjfGtdolvt78IqofnC9xsej",
	"QBuma0fIAwFI5GF2MujCvuhtpVFprfJov/euzr748bZ1ge5NGEBI/Ad7wAsTK9v3mhh3B84XLtn5tkFK",
	"sJSPKUroLH9frqZnvc1FEmyRM1JoDcqyJTEUC4NEXPWqyW9NaCWDNFhsgm4007KMpM9auwmeqZBwjEog",
	"17S8e66B3fFPEB9QvE8nzYQ5lCGSLSrV9Sq4vaGj5g7yJW9vav4OU3b/AWaPovecG8q5iwe3GVq9sCX1",
	"wt8KNguYXOGYNhzo8Vdk5qrpVxJypvpu6CsvnDQpgyDZ3IVewkbvyVHct86fhb4BGc99zAj5IXAnCTTb",
	"tRC2R/QLM5XEyY1SeYz6BmQRwV+MR4XdN/dcFzesvH69giBBaa8DC4IM+4qOXZ4temEunVrBcJ2jb+sO",
	"biMXdbu2sdVsRhdwv7j4oGdjitDEi62bz7EKzq1UXT+o5vrvUP/G4siN4eaNUczPqYqotupnovhubz9q",
	"Vu4NEOmUUv48nSyAg2IKiwX/4ppD3O1d6iGwOfnDo2phvUkhEYuYyFo7kwdTBUWSR9RHdp9FqiFjvlte",
	"S6a32BjUG9DYL9FKPd81VR9c1ZDGd+XuPi0uoWnO3NaIqJW/Xb8TtMT7yLrUuLmFRHlEvtnQVVU6czD5",
	"273ZX+DpX58Vj54+/svsr4+eP8rh2fMXjx7RF8/o4xdPH8OTvz5/9ggez796MXtSPHn2ZPbsybOvnr/I",
	"nz57PHv21Yu/3DN8yIBsAfW1u19O/k92Ui5EdvLuNDs3wLY4oRX7HszeoK48F9i4ziA1x5MIK8rKyUv/",
	"0//yJ+woF6t2eP/rxDVgmSy1rtTL4+Orq6uj8JPjBSaFZ1rU+fLYz4PtxDryyrvTJprcxr3gjrbWY9xU",
	"Rwon+Oz9N2fn5OTd6VFLMJOXk0dHj44eu961nFZs8nLyFH/C07PEfT92xDZ5+enzdHK8BFpiDRXzxwq0",
	"ZLl/JIEWW/d/dUUXC5BHmDBgf1o/OfZixfEnlxz/edez4zCk4vhTp4ZAsefLJmQg6sx7I8Ql+pK9oHNP",
	"9QIgjsIeuqeFwaN9E6MW1GnL0XwjVHTWTl5+iBlRXI+nqp6VLCf2HkZCNFgO6KSpDNHyAbSYBT3/W65m",
	"ONWj7MXHT8//+jkmLfUBees8e60rw0WBYmIRxsQfebj+VYPctoChm3sSgjH0+8ULZG009kIPZjsiP7kQ",
	"AXxqmYNPoPJ5SE1tMf9RAjAzRAyuBgsfsRsXxswhOTx59MgfYScgB2R17Kg1RHfXiTAIqDkkY73TojYi",
	"3ZjFZIiPIcX+pGxVHYNNxqkN5MZ6JCt6ad0nGIlGpEuNdBh1YayI5CZlwW2L59K/Y/OREXm3dqahdPF5",
	"yPaGaFQ+/jS0bpXM2u5cTFCsw+zn6eTZgZSw08rUKQ8ZAf0tLQ1+oPBVQSwEj+8OglNuwyTN3WHvuM/T",
	"yfO7xMEpN4yLlgTfDJpkRqidX3Jxxf2bRiCpVysqtyhu6DF77IrYoEPQv2dp3t6O1JzfDxPLkifTCWwq",
	"kMxofbScfPy872o5/uSbI+++iDqNcV2Qb/DByAtu12vHM2yINPZVUMHL6aWgHUsdf8LTmfz92JnT4w/R",
	"ImZFrWNfwyn+ZgdLn/TGwLrniw0rgpXkVOfLujr+hP9BwSgA2tb3PdYbfoxBOcefOmt1jwdr7f7efh6+",
	"sV6JAjxwYj63TaN3PT7+ZP8NJurQXiuzdOWPb4KXXi0hv5zEr7Ze8fPgK2LlRjorobD859mID7jQ4UfX",
	"OrPvUbpQ5MfvCZsT6E/BlJ/hgKNpS0MeY2vFbYtL//OW59Efh9vcKYuX+PnYqy0xybX75qfOn91TpZa1",
	"LsRVMAsa/Ky1egiZeVir/t/HV5Rpo8K7amzYi3n4sQZaHrvWC71f22rHgydYwjn4Mcx7iv56TB2qJ5VQ",
	"EbJ9T68CL90JvmwFAFD6a4EKQ+oC2mQzxpGCwkuo1fPtw6HoO7h6jNiCAW3eVTKspILlHKSgRU4V9gB2",
	"XUwGwvjn6LG7a4Hia1oQXwUjI614ceK0yc7S/lvYwOmf3t30ZyDXLAdyDqtKSCpZuSU/8Sat5NqM9Fsk",
	"TknzSxTAG4K1MZCSXnUzVWS8ykC3SY8vOgFEb8iS8qJ0edmixv7ehrLQtSmC4BpzAfkmVZWQCICt/geF",
	"DTdQR+SsCcbA0Iba6zAFrKEUFfoesKatnYRioIZ11oUXQZf/TyebzBziBfDMsZFsJoqt6+oykfRKb2yK",
	"9YBXWfkvwcgG0lnsqZNOEi/5IGj/uDUChkY1NBI05rQPH42Sik2fnf2gtRG9PD7GrJilUPp4YnTsrv0o",
	"fPixQZjvVTipJFtjMX5EmpDMqI5l5mwzbT+ryZOjR5PP/z8AAP//eE5KM6T9AAA=",
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
