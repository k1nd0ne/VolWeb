import axios from "axios";
import { getAuthHeaders } from "./auth";
import { useNavigate } from "react-router-dom";

// Create an Axios instance
const axiosInstance = axios.create();

// Add a request interceptor to include auth headers
axiosInstance.interceptors.request.use(
  (config) => {
    const authHeaders = getAuthHeaders();
    config.headers = { ...config.headers, ...authHeaders };
    return config;
  },
  (error) => Promise.reject(error),
);

// Add a response interceptor to handle token expiration
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (
      error.response &&
      error.response.status === 401 &&
      !originalRequest._retry
    ) {
      originalRequest._retry = true;
      const refreshToken = localStorage.getItem("refresh_token");

      if (refreshToken) {
        try {
          const response = await axios.post("/core/token/refresh/", {
            refresh: refreshToken,
          });

          if (response.status === 200) {
            const { access, refresh } = response.data;
            localStorage.setItem("access_token", access);

            if (refresh) {
              localStorage.setItem("refresh_token", refresh);
            }

            originalRequest.headers["Authorization"] = `Bearer ${access}`;
            return axiosInstance(originalRequest);
          }
        } catch (refreshError) {
          console.error("Token refresh failed", refreshError);
        }
      }
    }

    if (error.response && error.response.status === 401) {
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      window.location.href = "/login"; // Navigate to login
    }

    return Promise.reject(error);
  },
);

export default axiosInstance;
