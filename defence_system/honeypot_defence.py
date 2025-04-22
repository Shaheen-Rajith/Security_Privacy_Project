# honeypot_defence.py
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
import os

# Load the honeypot log CSV
log_path = "logs/honeypot_log.csv"
df = pd.read_csv(log_path, header=None)

# Assign correct column names
df.columns = ["timestamp", "ip", "user_agent", "method", "path", "email", "password"]

# Convert timestamp to datetime format
df["timestamp"] = pd.to_datetime(df["timestamp"])

# --- 1. IP Frequency Analysis ---
ip_counts = df["ip"].value_counts()

plt.figure(figsize=(8, 5))
ip_counts.plot(kind="bar", color="skyblue")
plt.title("Top IP Addresses Accessing the Honeypot")
plt.xlabel("IP Address")
plt.ylabel("Number of Requests")
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("logs/ip_frequency.png")
plt.close()

# --- 2. Hourly Access Heatmap ---
df["hour"] = df["timestamp"].dt.hour

plt.figure(figsize=(8, 5))
df["hour"].plot.hist(bins=24, color="orange", edgecolor="black")
plt.title("Access Time Distribution (by Hour)")
plt.xlabel("Hour of Day")
plt.ylabel("Number of Requests")
plt.xticks(range(0, 24))
plt.tight_layout()
plt.savefig("logs/access_heatmap.png")
plt.close()

# --- 3. User-Agent Keyword Frequency (optional word cloud) ---
# You can uncomment this if you want to generate a word cloud
"""
from wordcloud import WordCloud

ua_text = " ".join(df["user_agent"].astype(str))
wordcloud = WordCloud(width=800, height=400, background_color='white').generate(ua_text)

plt.figure(figsize=(10, 5))
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis("off")
plt.title("User-Agent Word Cloud")
plt.tight_layout()
plt.savefig("logs/user_agent_wordcloud.png")
plt.close()
"""

# --- 4. Print Summary to Console ---
print("📊 Honeypot Log Summary:")
print(f"Total entries: {len(df)}")
print("\nTop IPs:")
print(ip_counts.head())

print("\nHeatmap and IP frequency graphs saved in 'logs/' folder.")