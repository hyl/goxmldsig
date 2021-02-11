package xenc

import (
	"crypto/x509/pkix"
	"fmt"
)

var oid = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "streetAddress",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.17":                   "postalCode",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generationQualifier",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.1":  "userid",
}

func GetDNFromCert(namespace pkix.Name) string {
	emailAddress := "FMTOMGMediaDistribution@bbc.co.uk"

	for _, s := range namespace.ToRDNSequence() {
		for _, i := range s {
			if v, ok := i.Value.(string); ok {
				fmt.Printf("%s - %s\n", v, i.Type.String())
				if name, ok := oid[i.Type.String()]; ok {
					// <oid name>=<value>
					//fmt.Printf("%s\n", oid[i.Type.String()])
					if name == "emailAddress" {
						emailAddress = v
					}
				} else {
					//fmt.Printf("%s\n", i.Type.String())
				}
			} else {
				// <oid>=<value in default format> if value is not string
				//fmt.Printf("%s\n", i.Type.String)
				//subject = append(subject, fmt.Sprintf("%s=%v", i.Type.String, v))
			}
		}
	}
	return fmt.Sprintf("CN=%s, OU=%s, O=%s, L=%s, C=%s, emailAddress=%s", namespace.CommonName, namespace.OrganizationalUnit[0], namespace.Organization[0], namespace.Locality[0], namespace.Country[0], emailAddress)

}
