import validators
from urllib.parse import urlparse

url = "www.google.com"
result = validators.url(url)
print("validator url: ", bool(result))

if bool(result) is False:
    if "https://" in url:
        print()
    else:
        url = "http://"+url

result = validators.url(url)
print("validator url: ", bool(result))

parse_result = urlparse(url)

print(parse_result.scheme)
print(parse_result.netloc)