import axios from "axios";

// Create an Axios instance
const axiosInstance = axios.create();

// Add a request interceptor to include auth headers
axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("access_token");
    if (token) {
      config.headers = config.headers ?? new axios.AxiosHeaders();
      config.headers.set("Authorization", `Bearer ${token}`);
    }
    return config;
  },
  (error) => Promise.reject(error),
);

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
          window.location.href = "/login";
        }
      }
    }
    return Promise.reject(error);
  },
);

export default axiosInstance;
