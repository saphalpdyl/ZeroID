package smtp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	netsmtp "net/smtp"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"zeroid/aadarsha/validation"
)

type Sender struct {
	Host          string
	Port          int
	Username      string
	Password      string
	From          string
	InsecureLocal bool
}

func NewSenderFromEnv() (*Sender, error) {
	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil || port <= 0 || port > 65535 {
		return nil, errors.New("invalid SMTP_PORT")
	}
	s := &Sender{Host: os.Getenv("SMTP_HOST"), Port: port, Username: os.Getenv("SMTP_USER"), Password: os.Getenv("SMTP_PASSWORD"), From: os.Getenv("SMTP_FROM"), InsecureLocal: os.Getenv("SMTP_INSECURE_LOCAL") == "true"}
	if s.Host == "" || s.From == "" || strings.ContainsAny(s.From, "\r\n") {
		return nil, errors.New("missing SMTP host/from")
	}
	if s.InsecureLocal && s.Host != "localhost" && s.Host != "127.0.0.1" {
		return nil, errors.New("plaintext SMTP only permitted on loopback")
	}
	return s, nil
}
func (s *Sender) send(to, subject, text string) error {
	if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return errors.New("invalid mail headers")
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	client, err := netsmtp.NewClient(conn, s.Host)
	if err != nil {
		return err
	}
	defer client.Close()
	if !s.InsecureLocal {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP server must support STARTTLS")
		}
		if err = client.StartTLS(&tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if s.Username != "" {
		if err = client.Auth(netsmtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return err
		}
	}
	if err = client.Mail(s.From); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", s.From, to, subject, text)
	if _, err = writer.Write([]byte(msg)); err != nil {
		_ = writer.Close()
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
func (s *Sender) SendVerification(email, token, baseURL string) error {
	if err := safeParams(email, token, baseURL); err != nil {
		return err
	}
	link := strings.TrimRight(baseURL, "/") + "/verify-email?token=" + url.QueryEscape(token)
	return s.send(email, "Verify your ZeroID email", "Open this link to verify your ZeroID email (expires in 15 minutes, single use):\n"+link+"\nIf you did not request this, ignore it.")
}
func (s *Sender) SendPasswordReset(email, token, baseURL string) error {
	if err := safeParams(email, token, baseURL); err != nil {
		return err
	}
	link := strings.TrimRight(baseURL, "/") + "/reset-password?token=" + url.QueryEscape(token)
	return s.send(email, "Reset your ZeroID password", "Use this link to reset your ZeroID password (expires in 15 minutes, single use):\n"+link+"\nIf you did not request this, ignore it.")
}
func safeParams(email, token, baseURL string) error {
	if err := validation.Email(email); err != nil {
		return err
	}
	if err := validation.Token(token); err != nil {
		return err
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"))) || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("invalid base URL")
	}
	return nil
}
