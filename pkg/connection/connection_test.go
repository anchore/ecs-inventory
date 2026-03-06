package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnchoreInfo_IsValid(t *testing.T) {
	tests := []struct {
		name string
		info AnchoreInfo
		want bool
	}{
		{
			name: "all fields populated",
			info: AnchoreInfo{
				URL:      "https://ancho.re",
				User:     "admin",
				Password: "foobar",
				Account:  "test",
			},
			want: true,
		},
		{
			name: "empty URL",
			info: AnchoreInfo{
				URL:      "",
				User:     "admin",
				Password: "foobar",
			},
			want: false,
		},
		{
			name: "empty User",
			info: AnchoreInfo{
				URL:      "https://ancho.re",
				User:     "",
				Password: "foobar",
			},
			want: false,
		},
		{
			name: "empty Password",
			info: AnchoreInfo{
				URL:      "https://ancho.re",
				User:     "admin",
				Password: "",
			},
			want: false,
		},
		{
			name: "all empty",
			info: AnchoreInfo{},
			want: false,
		},
		{
			name: "Account empty but URL User Password set",
			info: AnchoreInfo{
				URL:      "https://ancho.re",
				User:     "admin",
				Password: "foobar",
				Account:  "",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.info.IsValid())
		})
	}
}
