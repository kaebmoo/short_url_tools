from expression_generator import ExpressionGenerator

# Example usage
urls = [
    "http://a.b.com/1/2.html?param=1",
    "http://a.b.c.d.e.f.com/1.html",
    "http://1.2.3.4/1/",
    "http://example.co.uk/1",
    "https://codinggun.com/security/jwt/"
]

for url in urls:
    print(f"URL: {url}")
    generator = ExpressionGenerator(url)
    for expression in generator.Expressions():
        print(expression.Value())
    print()
