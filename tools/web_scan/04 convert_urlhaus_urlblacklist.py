import pandas as pd
import numpy as np

# Define the input and output file paths
input_file_path = '/Users/seal/Documents/GitHub/short_url_tools/tools/web_scan/urlhaus_online_urls.csv'
output_file_path = '/Users/seal/Documents/GitHub/short_url_tools/tools/web_scan/urlhaus_blacklist.csv'

# Read the input CSV file
df = pd.read_csv(input_file_path)

# Transform the data
df_transformed = pd.DataFrame({
    'url': df['url'],
    'category': df['threat'],
    'date_added': pd.to_datetime(df['dateadded']).dt.strftime('%Y-%m-%d'),
    'reason': df['tags'],
    'status': np.where(df['url_status'] == 'online', 1, 0)
})

# Save the transformed DataFrame to the output CSV file
df_transformed.to_csv(output_file_path, index=False)

print(f"Data has been successfully transformed and saved to {output_file_path}")
