import re

url = "http://www.google.net"
regex_url = "(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})"
try:
    re.compile(regex_url)
    is_valid = True
    print("Regular expression is valid.")
    url_match = re.match(regex_url, url)
    print(url_match)

    if url_match is None:
        print("URL not match")
except re.error:
    is_valid = False
    print("Regular expression is invalid.")

