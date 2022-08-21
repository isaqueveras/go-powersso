package gopowersso

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestParseJWT(t *testing.T) {
	var scenarios = []struct {
		token        string
		secret       string
		expectError  bool
		expectClaims jwt.MapClaims
	}{
		// invalid formatted JWT token
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9",
			"test",
			true,
			nil,
		},
		// properly formatted JWT token with INVALID claims and INVALID secret
		// {"name": "test", "exp": 1516239022}
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MTUxNjIzOTAyMn0.xYHirwESfSEW3Cq2BL47CEASvD_p_ps3QCA54XtNktU",
			"invalid",
			true,
			nil,
		},
		// properly formatted JWT token with INVALID claims and VALID secret
		// {"name": "test", "exp": 1516239022}
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MTUxNjIzOTAyMn0.xYHirwESfSEW3Cq2BL47CEASvD_p_ps3QCA54XtNktU",
			"test",
			true,
			nil,
		},
		// properly formatted JWT token with VALID claims and INVALID secret
		// {"name": "test", "exp": 1898636137}
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MTg5ODYzNjEzN30.gqRkHjpK5s1PxxBn9qPaWEWxTbpc1PPSD-an83TsXRY",
			"invalid",
			true,
			nil,
		},
		// properly formatted EXPIRED JWT token with VALID secret
		// {"name": "test", "exp": 1652097610}
		{
			"eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6OTU3ODczMzc0fQ.0oUUKUnsQHs4nZO1pnxQHahKtcHspHu4_AplN2sGC4A",
			"test",
			true,
			nil,
		},
		// properly formatted JWT token with VALID claims and VALID secret
		// {"name": "test", "exp": 1898636137}
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImV4cCI6MTg5ODYzNjEzN30.gqRkHjpK5s1PxxBn9qPaWEWxTbpc1PPSD-an83TsXRY",
			"test",
			false,
			jwt.MapClaims{"name": "test", "exp": 1898636137.0},
		},
		// properly formatted JWT token with VALID claims (without exp) and VALID secret
		// {"name": "test"}
		{
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCJ9.ml0QsTms3K9wMygTu41ZhKlTyjmW9zHQtoS8FUsCCjU",
			"test",
			false,
			jwt.MapClaims{"name": "test"},
		},
	}

	for i, scenario := range scenarios {
		result, err := parseJWT(scenario.token, scenario.secret)
		if scenario.expectError && err == nil {
			t.Errorf("(%d) Expected error got nil", i)
		}

		if !scenario.expectError && err != nil {
			t.Errorf("(%d) Expected nil got error %v", i, err)
		}

		if len(result) != len(scenario.expectClaims) {
			t.Errorf("(%d) Expected %v got %v", i, scenario.expectClaims, result)
		}

		for k, v := range scenario.expectClaims {
			v2, ok := result[k]
			if !ok {
				t.Errorf("(%d) Missing expected claim %q", i, k)
			}

			if v != v2 {
				t.Errorf("(%d) Expected %v for %q claim, got %v", i, v, k, v2)
			}
		}
	}
}
