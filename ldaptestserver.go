package main

/* This is a simple LDAP server for testing purposes

1) good bind / good user

ldapsearch -H ldap://127.0.0.1:10000 -b dc=example,dc=com \
  -D mail=bind@example.com,dc=example,dc=com -w 1234 \
  '(mail=adam@example.com)' uid

2) good bind / non-existen user

ldapsearch -H ldap://127.0.0.1:10000 -b dc=example,dc=com \
  -D mail=bind@example.com,dc=example,dc=com -w 1234 \
  '(mail=nonexistent@example.com)' uid

3) wrong bind pw

ldapsearch -H ldap://127.0.0.1:10000 -b dc=example,dc=com \
  -D mail=bind@example.com,dc=example,dc=com -w 4321 \
  '(mail=nonexistent@example.com)' uid
*/

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/vjeantet/goldap/message"
	ldap "github.com/vjeantet/ldapserver"
)

func matches(filter message.Filter, entry map[string]interface{}) bool {
	switch f := filter.(type) {
	case message.FilterOr:
		for _, sf := range f {
			if matches(sf, entry) {
				return true
			}
		}
		return false
	case message.FilterAnd:
		for _, sf := range f {
			if !matches(sf, entry) {
				return false
			}
		}
		return true
	case message.FilterNot:
		return !matches(f, entry)
	case message.FilterEqualityMatch:
		expected := string(f.AssertionValue())
		log.Printf("`%s'!=`%v'", entry[string(f.AttributeDesc())], expected)
		switch value := entry[string(f.AttributeDesc())].(type) {
		case string:
			return entry[string(f.AttributeDesc())] == expected
		case []string:
			for _, s := range value {
				if s == expected {
					return true
				}
			}
			return false
		}
	}
	return true
}

func main() {
	binds := map[string]string{
		"mail=bind@example.com,dc=example,dc=com": "1234",
		"mail=adam@example.com,dc=example,dc=com": "adam1234",
		"mail=john@example.com,dc=example,dc=com": "john1234",
	}

	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(func(w ldap.ResponseWriter, m *ldap.Message) {
		r := m.GetBindRequest()
		res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

		if binds[string(r.Name())] == string(r.AuthenticationSimple()) {
			w.Write(res)
			return
		}

		log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
		res.SetResultCode(ldap.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage("invalid credentials")
		w.Write(res)
	})
	routes.Search(func(w ldap.ResponseWriter, m *ldap.Message) {
		r := m.GetSearchRequest()
		log.Printf("Request BaseDn=%s", r.BaseObject())
		log.Printf("Request Filter=%s", r.Filter())
		log.Printf("Request FilterString=%s", r.FilterString())
		log.Printf("Request Attributes=%s", r.Attributes())
		log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

		db := []map[string]interface{}{
			{
				"cn":   "Adam Doe",
				"mail": "adam@example.com",
				"uid":  "199",
				"objectClass": []string{
					"Gperson",
					"Gstaff",
					"top",
					"posixAccount",
					"inetOrgPerson",
				},
			},
			{
				"cn":   "John Doe",
				"mail": "john@example.com",
				"uid":  "11",
				"objectClass": []string{
					"Gperson",
					"Gstudent",
					"top",
					"posixAccount",
					"inetOrgPerson",
				},
			},
		}
		var matchingUser map[string]interface{}
		for _, user := range db {
			if matches(r.Filter(), user) {
				matchingUser = user
				break
			}
		}
		if matchingUser == nil {
			res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
			w.Write(res)
			return
		}
		e := ldap.NewSearchResultEntry("mail=" + matchingUser["mail"].(string) + ",dc=example,dc=com")
		for _, attribute := range r.Attributes() {
			attributeValue := matchingUser[string(attribute)]
			switch value := attributeValue.(type) {
			case string:
				e.AddAttribute(message.AttributeDescription(attribute), message.AttributeValue(value))
			case []string:
				for _, item := range value {
					e.AddAttribute(message.AttributeDescription(attribute), message.AttributeValue(item))
				}
			}
		}
		w.Write(e)
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
		w.Write(res)
	}).
		// BaseDn("dc=example,dc=com").
		Label("Search - Company Root")
	server.Handle(routes)

	go server.ListenAndServe("127.0.0.1:10000")

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)
	server.Stop()
}
