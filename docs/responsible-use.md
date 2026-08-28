# Responsible use

garga is a defensive Elasticsearch assessment tool. Use it only against systems you own or are
explicitly authorized to test. Unauthorized scanning, credential guessing, or exploitation is
outside the project's purpose and may be illegal.

## Required authorization

Before running garga:

- obtain written or otherwise recorded permission that names the in-scope hosts, networks, and
  time window;
- confirm the operator identity that will run the tool;
- keep that authorization with the engagement record.

Do not treat a public IP, a default Elasticsearch port, or a shared staging environment as
implicit consent.

## Safety boundary

The default assessment path is read-only. garga must not:

- exploit vulnerabilities or attempt remote code execution;
- create, update, or delete indices, documents, users, or cluster settings;
- spray credentials unless an operator explicitly runs `garga auth-audit` or `garga auth-detect`
  with an explicit stdin list or local list file.

`garga auth-check` verifies one credential. `garga auth-audit` is isolated, rate-limited, and
attempt-limited for short explicit lists. `garga auth-detect` adds bounded stuffing, spraying,
brute-force, and dictionary modes. None of these commands accepts a `--password` flag.

`garga scan` and `garga vuln` remain bound to the same GET-only, non-state-changing contract.
They do not send credentials.

`garga secrets` inspects authorized cluster mappings and a bounded document sample. It does not
export indices. Use it only with valid access to in-scope clusters. Default reports mask
secrets; treat the PDF artifact as confidential.

## Handling output

Reports, logs, and signature databases can describe exposed services. Store them as sensitive
engagement artifacts. Redact credentials before sharing. Do not paste production host lists,
tokens, or customer data into public issues.

## If observed traffic is unexpected

Stop the run. Capture the command line (without secrets), configuration keys, garga version, and
the unexpected request method or path. Report the behavior privately using [SECURITY.md](../SECURITY.md)
when it appears to violate the safe-by-default contract.
