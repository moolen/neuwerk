package e2e

import (
	// nolint

	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"

	// nolint
	. "github.com/onsi/gomega"
)

var _ = Describe("hostname test", Label("hostname"), func() {
	It("Valid hosts", func() {
		// ok for https
		for _, host := range httpsOnlyHosts {
			url := fmt.Sprintf("https://%s", host)
			GinkgoLogr.Info("testing host", "url", url)
			start := time.Now()
			res, err := httpClient.Get(url)
			GinkgoLogr.Info("request took", "ms", time.Since(start).Milliseconds())
			Expect(err).To(BeNil())
			res.Body.Close()
			Expect(res.StatusCode).To(Equal(http.StatusOK))
		}

		// timeout for http
		for _, host := range httpsOnlyHosts {
			url := fmt.Sprintf("http://%s", host)
			GinkgoLogr.Info("testing host", "url", url)
			start := time.Now()
			_, err := httpClient.Get(url)
			GinkgoLogr.Info("request took", "ms", time.Since(start).Milliseconds())
			Expect(err).ToNot(BeNil())
		}

		// timeout for invalid
		protos := []string{"http", "https"}
		for _, host := range blockedhosts {
			for _, proto := range protos {
				url := fmt.Sprintf("%s://%s", proto, host)
				GinkgoLogr.Info("testing host", "url", url)
				_, err := httpClient.Get(url)
				Expect(err).ToNot(BeNil())
			}
		}
	})
})
