package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func parseCert(ca []byte) (*x509.Certificate, error) {
	caBlock, _ := pem.Decode(ca)
	if caBlock == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	caDer, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return caDer, err
}

type Info struct {
	CommonName         string   `json:"common_name"`         // CN
	Country            []string `json:"country"`             // C
	Organization       []string `json:"organization"`        // O
	OrganizationalUnit []string `json:"organizational_unit"` // Ou
	Locality           []string `json:"locality"`            // L
	Province           []string `json:"province"`            // ST
}

type Subject struct {
	Info
}
type Issuer struct {
	Info
}

type CertInfoResp struct {
	Subject      Subject  `json:"subject"`       // 主题
	Issuer       Issuer   `json:"issuer"`        // 颁发者
	NotBefore    string   `json:"not_before"`    // 有效期开始
	NotAfter     string   `json:"not_after"`     // 有效期结束
	SerialNumber string   `json:"serial_number"` // 序列号
	DNSNames     []string `json:"dns_names"`     // DNS名称
	IPAddresses  []string `json:"ip_addresses"`  // IP地址
	RootCA       bool     `json:"root_ca"`       // 是否是根CA
	Validity     int      `json:"validity"`      // 有效期
}

type CommonResp struct {
	Data any    `json:"data"`
	Msg  string `json:"msg"`
	Code int    `json:"code"`
}

func certInfoHandle(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Default().Println(err)
		return
	}
	if len(body) == 0 {
		httpErr(w, "请求体不能为空")
		return
	}

	cert, err := parseCert(body)
	if err != nil {
		httpErr(w, "解析证书失败: "+err.Error())
		return
	}

	certinfo := CertInfoResp{
		Subject: Subject{
			Info: Info{
				CommonName:         cert.Subject.CommonName,
				Country:            cert.Subject.Country,
				Organization:       cert.Subject.Organization,
				OrganizationalUnit: cert.Subject.OrganizationalUnit,
				Locality:           cert.Subject.Locality,
				Province:           cert.Subject.Province,
			}},
		Issuer: Issuer{
			Info: Info{
				CommonName:         cert.Issuer.CommonName,
				Country:            cert.Issuer.Country,
				Organization:       cert.Issuer.Organization,
				OrganizationalUnit: cert.Issuer.OrganizationalUnit,
				Locality:           cert.Issuer.Locality,
				Province:           cert.Issuer.Province,
			}},
		NotBefore:    cert.NotBefore.Local().String(),
		NotAfter:     cert.NotAfter.Local().String(),
		Validity:     int(cert.NotAfter.Sub(cert.NotBefore).Seconds() / 86400), // 有效期天数
		SerialNumber: cert.SerialNumber.String(),
		DNSNames:     cert.DNSNames,
		RootCA:       cert.IsCA,
		IPAddresses: func(ips []net.IP) []string {
			var ipStrs []string
			for _, ip := range ips {
				ipStrs = append(ipStrs, ip.String())
			}
			return ipStrs
		}(cert.IPAddresses),
	}

	httpOk(w, certinfo)
}

func httpOk(w http.ResponseWriter, data any) {
	httpResp(w, data, "success", 0)
}

func httpErr(w http.ResponseWriter, msg string) {
	httpResp(w, nil, msg, 1)
}

func httpResp(w http.ResponseWriter, data any, msg string, code int) {
	ret, err := json.Marshal(CommonResp{
		Data: data,
		Msg:  msg,
		Code: code,
	})
	if err != nil {
		log.Default().Println(err)
		return
	}
	log.New(os.Stdout, "http: ", log.LstdFlags).Println("响应:", string(ret))

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Write(ret)
}

func main() {
	key := flag.String("key", "", "key file")
	cert := flag.String("cert", "", "cert")
	flag.Parse()

	http.HandleFunc("/certinfo", certInfoHandle)
	svr := http.Server{
		Addr:         ":8888",
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}

	go func() {
		if *key == "" || *cert == "" {
			fmt.Println("http服务启动成功")
			if err := svr.ListenAndServe(); err != nil {
				log.Fatalln(err)
			}
		}
	}()

	// 优雅的关闭
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	<-ctx.Done()

	stop()

	timeoutCTX, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := svr.Shutdown(timeoutCTX); err != nil {
		fmt.Println(err)
	}
}
