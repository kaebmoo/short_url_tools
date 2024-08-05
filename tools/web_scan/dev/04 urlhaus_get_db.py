import requests
import pandas as pd
from io import StringIO

# Fetch data from the URL
url = "https://urlhaus.abuse.ch/downloads/csv_online/"
response = requests.get(url)
data = response.text

# Adjust the header line index
header_line_index = 8

# Process the response text
data_lines = data.splitlines()
header_line = data_lines[header_line_index].replace('#', '').replace(' ', '')
csv_data = "\n".join([header_line] + data_lines[header_line_index + 1:])

# Load the CSV data into a pandas DataFrame
df = pd.read_csv(StringIO(csv_data))
print(df.columns)

# Save the DataFrame to a CSV file
df.to_csv('tools/web_scan/urlhaus_online_urls.csv', index=False, header=header_line)

print("CSV file saved as 'urlhaus_online_urls.csv'")
