import axios from "axios";

const api = axios.create({
  baseURL: "http://127.0.0.1:8000",
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 10000,
});

export const healthCheck = async () => {
  const response = await api.get("/health");
  return response.data;
};

export const getAlerts = async ({
  limit = 50,
  offset = 0,
  decision = null,
} = {}) => {
  const params = {
    limit,
    offset,
  };

  if (decision) {
    params.decision = decision;
  }

  const response = await api.get("/alerts", { params });

  return response.data;
};

export const getStatistics = async () => {
  const response = await api.get("/statistics");
  return response.data;
};

export const predictTraffic = async (features) => {
  const response = await api.post("/predict", features);
  return response.data;
};

export const predictTrafficBatch = async (samples) => {
  const response = await api.post("/predict/batch", {
    samples,
  });

  return response.data;
};

export default api;
