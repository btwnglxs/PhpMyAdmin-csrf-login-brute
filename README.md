# PhpMyAdmin-csrf-login-brute

Python-script to brute phpMyAdmin with CSRF bypass.

## Features

* **CSRF bypass** The script dynamically parses the authorization page before sending a POST request, extracts the current CSRF-token (`token`), and inserts it into the form.
* **Multithreading:** A thread-safe queue (`queue.Queue`) has been implemented for the parallel processing of a wordlist.

## Operating logic

* Data collection ans parsing: `requests`, `BeautifulSoup4`, `re`
* Concurrency: `threading`, `queue`

## Usage

### Installing dependencies
```bash
pip install requests beautifulsoup4
```

### Usage syntax
```bash
python pma_brute.py -u <URL> -w <path_to_wordlist> [options]
```

Usage example :
```bash
python pma_brute.py -u http://192.168.31.97/phpmyadmin/ -w /usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt -t 40 -n administrator
```

## Background to the creation of the script

During a penetration test of a virtual lab environment, it was necessary to perform a brute-force attack against a `PhpMyAdmin` administrative panel (it didn't, actually, as said in description to the lab) that had been exposed to the external network perimeter. Since the solution available within `msfconsole` (`auxiliary/scanner/http/phpmyadmin_login`) didn't worked, I decided to write a Python script for this purpose.

I also tweaked the script by adding CLI arguments; although it was originally intended as a "one-off" script, all the data for the brute-force process had been hardcoded.

## Disclaimer

The author is not responsible for any possible damage caused by using this software for illegal purposes.
