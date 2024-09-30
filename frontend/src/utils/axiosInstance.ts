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
    // if token is expired
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const refreshToken = localStorage.getItem("refresh_token");
      if (refreshToken) {
        const response = await axios.post("/core/token/refresh/", {
          refresh: refreshToken,
        });
        if (response.status === 200) {
          const { access } = response.data;
          localStorage.setItem("access_token", access);
          originalRequest.headers["Authorization"] = `Bearer ${access}`;
          return axiosInstance(originalRequest);
        }
      }
    }

    // Log out the user if cannot refresh token or no refresh token
    if (error.response.status === 401) {
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      localStorage.removeItem("username");
      window.location.href = "/login"; // Navigate to login
    }

    return Promise.reject(error);
  },
);

export default axiosInstance;
