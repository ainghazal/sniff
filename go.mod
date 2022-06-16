module github.com/ainghazal/sniff

go 1.18

require (
	github.com/go-gost/tls-dissector v0.0.1
	github.com/google/gopacket v1.1.19
)

replace github.com/go-gost/tls-dissector => ../tls-dissector

require golang.org/x/sys v0.0.0-20190412213103-97732733099d // indirect
