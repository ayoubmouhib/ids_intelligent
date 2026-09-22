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
  const params = { limit, offset };
  if (decision) {
    params.decision = decision;
  }
  const response = await api.get("/alerts", { params });
  return response.data;
};

export const getStatistics = async ({
  decision = null,
  source_ip = null,
  start_time = null,
  end_time = null,
} = {}) => {
  const params = {};

  if (decision) params.decision = decision;
  if (source_ip) params.source_ip = source_ip;
  if (start_time) params.start_time = start_time;
  if (end_time) params.end_time = end_time;

  const response = await api.get("/statistics", { params });

  return response.data;
};

export const getStatisticsTimeline = async ({
  hours = 24,
  bucket_minutes = 60,
  decision = null,
  source_ip = null,
  start_time = null,
  end_time = null,
} = {}) => {
  const params = {
    hours,
    bucket_minutes,
  };

  if (decision) {
    params.decision = decision;
  }

  if (source_ip) {
    params.source_ip = source_ip;
  }

  if (start_time) {
    params.start_time = start_time;
  }

  if (end_time) {
    params.end_time = end_time;
  }

  const response = await api.get("/statistics/timeline", {
    params,
  });

  return response.data;
};

export const getZeekEvents = async ({
  limit = 50,
  offset = 0,
  decision = null,
  source_ip = null,
  start_time = null,
  end_time = null,
} = {}) => {
  const params = {
    limit,
    offset,
  };

  if (decision) {
    params.decision = decision;
  }

  if (source_ip) {
    params.source_ip = source_ip;
  }

  if (start_time) {
    params.start_time = start_time;
  }

  if (end_time) {
    params.end_time = end_time;
  }

  const response = await api.get("/zeek/events", { params });

  return response.data;
};

export const predictTraffic = async (features) => {
  const response = await api.post("/predict", features);
  return response.data;
};

export const predictTrafficBatch = async (samples) => {
  const response = await api.post("/predict/batch", { samples });
  return response.data;
};

export default api;
