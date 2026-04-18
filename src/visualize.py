import os
import pandas as pd
import matplotlib.pyplot as plt


def plot_traffic():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "data", "traffic_log.csv")

    df = pd.read_csv(csv_path)

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Plot packet count
    plt.figure()
    plt.plot(df["timestamp"], df["packet_count"])
    plt.title("Packet Count Over Time")
    plt.xlabel("Time")
    plt.ylabel("Packets")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Plot anomalies
    plt.figure()
    anomaly_points = df[df["result"] == "ANOMALY"]

    plt.plot(df["timestamp"], df["packet_count"], label="Packet Count")
    plt.scatter(anomaly_points["timestamp"], anomaly_points["packet_count"], label="Anomalies")

    plt.legend()
    plt.title("Anomaly Detection Visualization")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    plot_traffic()