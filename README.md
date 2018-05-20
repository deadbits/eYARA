# eYARA
eYARA is an application used to scan incoming email against YARA rule sets to look for malware and other suspicious content within the emails and their attachments.

## Functionality
- Run as background process to scan all inbound emails against YARA rule
    - Rules are built-in but you may also provide custom rules
- Match YARA rules against only the email body or their attachments
- Optionally store the malicious artifacts for futher analysis
- Extract Indicators of Compromise (IOCs) from matched emails
    - IPv4 / IPv4 Addresses
    - Domains
    - Filenames
    - Hashes (MD5, SHA1, SHA256, SHA512)
    - URLs
    - Potential ZIP file passwords
- Run CLI tool against individual email or folder of emails for quick analysis of an already delivered message
- Set various `meta` options within the YARA rule to perform different actions when a match is made. _Most options accept either "true" or "false" as their values, while "move" requires an Inbox folder name_
    - Delete email from inbox if matched rules
      - `discard_msg = "true"`
    - Save email and attachment artifacts for further inspections
      - `store_artifacts = "true"`
    - Move matched emails to specific folder
      - `move_msg = "Spam"`
    - Send Slack alert when email matches a rule. Slack API token is set in the `etc/eyara.conf` file
      - `slack_alert = "true"`
      - `slack_channel = "name"`
    - Check only the message body 
      - `scan_body = "true"`
    - Check only the message attachments
      - `scan_attachment = "true"`
      
## CLI Utility
Individual emails or entire directories of emails can be scanned using a smaller command line utility. This performs a subset of the functions that the background service provides. You have the option of storing the scan report to a specified directory as a JSON file or sending the formatted output to standard out (for use with `jq` or to pipe into other utilities or files).

**Usage:**
- `eyara-cli --dir /var/mail/adam/ --ruleset standard --report /opt/eyara/var/reports`
- `eyara-cli --file mymessage.eml --ruleset custom --report stdout | jq '.'`
      
## Artifact Storage
If you choose to store the malicious artifacts, the raw email message and attachments will be copied into a sub-directory of `/opt/eyara/var/storage/email/` and `/opt/eyara/var/storage/attachments` respectively. Each sub-directory is named after the time the email came in and the MD5 hash of the artifact itself. Within the directory is the stored object, along with the JSON formatted report of the artifact created by eYARA.

For emails, the JSON report will include all extracted headers, the message body, a variety of spoofed email checks, a list of attachments and their metadata with the payload removed, the YARA rules that were matched, the time the email was first seen, and the time the email was done being processed by eYARA.

For attachments, the JSON reports includes the filenames, file type, file size, MD5 hash, the YARA rules that were matched,the time the email was first seen, and the time the email was done being processed by eYARA. 

## YARA rule syntax
Below is an example of a Yara rule with all of the options shown to get an idea of what a custom rule may look like.
`meta` options that are "false" do not need to be included, but are simply shown here for the sake of completion.

This example rule will remove the offending message from your Inbox, store the raw email message and attachment in 
```
rule eYARA_Suspsected_Phishing_01 : phishing
{
    meta:
        created_at      = "05/15/2018"
        discard_msg     = "true"
        move_msg        = "false"
        store_artifacts = "true"
        scan_body       = "true"
        scan_attachment = "false"
        slack_alert     = "true"
        slack_channel   = "eYARA Alerts"
    strings:
        $attach = "Content-Disposition: attachment"
        $from = "From "
        $received = "\x0aReceived:"
        $return = "\x0aReturn-Path:"
        
        $body0 = "Invoice" nocase
        $body1 = "Factura" nocase
        $body2 = "Unauthorized" nocase
        $body3 = "Expired" nocase
        $body4 = "Deleted" nocase
        $body5 = "Suspended" nocase
        $body6 = "Revoked" nocase
        $body7 = "resume attached" nocase
        $body8 = "attached is my resume" nocase
        $body9 = "attach is my resume" nocase
        $body10 = "PDF file is my resume" nocase
        
    condition:
        (
          ($from at 0) or
          ($received in (0 .. 2048)) or
          ($return in (0 .. 2048)) and
           $attach
        ) 
        and
        (
          any of ($body*
        )
}
```
        
