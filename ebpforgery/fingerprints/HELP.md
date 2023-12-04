# Help for creating new fingerprints #

You will need to read and understand: https://nmap.org/book/osdetect-methods.html

- Find the nmap OS signature you want to mimic in the NMAP repository. Its the nmap OS database.

- Create a new `personality.c` and copy the signature into `fingerprints/personality.fingerprint`.

- Setup a machine on the same network to probe your new personality (for nmap and testing).

- Run nmap with OS detection:
```
$ sudo nmap -vv -O <IP>
```

- Grab the signature the nmap returns and add it to `nmap.output` to get a simplified look.
```
vi nmap.output && lf=$'\n'; cat nmap.output | sed 's/OS://g' | tr "$lf" " " | sed "s/)/)\\$lf/g"
```

- Paste the pretty output into the `personality.fingerprint` so you can compare whats different.