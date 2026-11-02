package process

import "encoding/base64"

func b64std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
