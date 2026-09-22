# @summary A DNS name that can appear in a certificate, including wildcards.
type Certmanager::Dnsname = Pattern[/\A(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\z/]
