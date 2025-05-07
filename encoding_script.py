import urllib.parse

username = "heidi@everychart.io"  # Replace with your actual username
password = "h@ppyPupp13sH0p"  # Replace with your actual password
cluster = "cluster0.85lwk"

# URL encode the username and password
encoded_username = urllib.parse.quote_plus(username)
encoded_password = urllib.parse.quote_plus(password)

# Construct the connection string
uri = f"mongodb+srv://{encoded_username}:{encoded_password}@{cluster}.mongodb.net/"

print(uri)  # Use this URI in your .env file