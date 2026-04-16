from sklearn.ensemble import IsolationForest
import numpy as np


class AnomalyDetector:
    def __init__(self):
        # contamination = expected % of anomalies
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.trained = False

    def train(self, data):
        self.model.fit(data)
        self.trained = True

    def predict(self, features):
        if not self.trained:
            return "Training..."

        prediction = self.model.predict([features])

        if prediction[0] == -1:
            return "ANOMALY"
        else:
            return "NORMAL"