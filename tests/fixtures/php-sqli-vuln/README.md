# php-sqli-vuln

Deliberately vulnerable PHP fixture for the codered Plan F end-to-end test.

`index.php` reads `$_GET['id']` (taint source) and concatenates it into a raw
SQL string passed to `mysqli_query` (taint sink, CWE-89) with no sanitization.

The e2e test asserts the PHP pipeline produces: a `.php` dataflow edge, a
`$_GET -> mysqli_query` taint chain, and at least one SAST finding.

Do not "fix" this file — the vulnerability is the test fixture.
