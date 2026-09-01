/*
 * Copyright [2022] [tinkernels (github.com/tinkernels)]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package zerosslIPCert

import "fmt"

// RevokeReason holds the reason values accepted by the revoke endpoint.
var RevokeReason = struct {
	Unspecified          string
	KeyCompromise        string
	AffiliationChanged   string
	Superseded           string
	CessationOfOperation string
}{
	Unspecified:          "Unspecified",
	KeyCompromise:        "keyCompromise",
	AffiliationChanged:   "affiliationChanged",
	Superseded:           "Superseded",
	CessationOfOperation: "cessationOfOperation",
}

// ApiErrorModel is the error object ZeroSSL embeds in a response body.
type ApiErrorModel struct {
	Code int    `json:"code"`
	Type string `json:"type"`
	Info string `json:"info"`
}

func (e *ApiErrorModel) Error() string {
	if e.Info != "" {
		return fmt.Sprintf("ZeroSSL API error %d (%s): %s", e.Code, e.Type, e.Info)
	}
	return fmt.Sprintf("ZeroSSL API error %d (%s)", e.Code, e.Type)
}

// ActionResultModel is the response of endpoints that only acknowledge an action,
// such as cancel and revoke. NOTICE: ZeroSSL answers with HTTP 200 even on failure,
// so the body has to be inspected. "success" comes back as 1 on success and as
// false on failure, hence the interface{}.
type ActionResultModel struct {
	Success interface{}    `json:"success"`
	Error   *ApiErrorModel `json:"error"`
}

// IsSuccess reports whether the API acknowledged the action.
func (m ActionResultModel) IsSuccess() bool {
	switch v_ := m.Success.(type) {
	case bool:
		return v_
	case float64:
		return v_ != 0
	case string:
		return v_ == "1" || v_ == "true"
	}
	return false
}

// Err turns an unsuccessful result into an error.
func (m ActionResultModel) Err() error {
	if m.IsSuccess() {
		return nil
	}
	if m.Error != nil {
		return m.Error
	}
	return fmt.Errorf("ZeroSSL API did not acknowledge the action")
}
