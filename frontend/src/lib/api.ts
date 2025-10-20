import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5001';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor to handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export interface User {
  username: string;
}

export interface Credential {
  site: string;
  account: string;
  site_password: string;
  v: string;
}

export interface AuthResponse {
  message: string;
  token?: string;
  username?: string;
}

export interface CredentialResponse {
  message?: string;
  site?: string;
  account?: string;
  credentials?: Credential[];
}

// Auth API
export const authAPI = {
  signup: async (username: string, password: string): Promise<AuthResponse> => {
    const response = await api.post('/auth/signup', { username, password });
    return response.data;
  },

  login: async (username: string, password: string): Promise<AuthResponse> => {
    const response = await api.post('/auth/login', { username, password });
    return response.data;
  },

  rotatePassword: async (currentPassword: string, newPassword: string): Promise<AuthResponse> => {
    const response = await api.put('/auth/rotate', { 
      current_password: currentPassword, 
      new_password: newPassword 
    });
    return response.data;
  },
};

// Credentials API
export const credentialsAPI = {
  addCredential: async (site: string, account: string, sitePassword: string): Promise<CredentialResponse> => {
    const response = await api.post('/credentials/', { 
      site, 
      account, 
      site_password: sitePassword 
    });
    return response.data;
  },

  getCredentials: async (): Promise<CredentialResponse> => {
    const response = await api.get('/credentials/');
    return response.data;
  },
};

export default api;
