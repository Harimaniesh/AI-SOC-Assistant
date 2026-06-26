const BASE_API_URL = ''; // Proxied via Vite config to backend port 8000

export const getAuthToken = () => localStorage.getItem('soc_token');
export const setAuthToken = (token) => localStorage.setItem('soc_token', token);
export const removeAuthToken = () => localStorage.removeItem('soc_token');

export const getAuthUser = () => {
  const username = localStorage.getItem('soc_user');
  const role = localStorage.getItem('soc_role');
  return username ? { username, role } : null;
};

export const setAuthUser = (username, role) => {
  localStorage.setItem('soc_user', username);
  localStorage.setItem('soc_role', role);
};

export const clearAuth = () => {
  removeAuthToken();
  localStorage.removeItem('soc_user');
  localStorage.removeItem('soc_role');
};

/**
 * Handle HTTP response and automatically log out on 401 Unauthorized
 */
const handleResponse = async (response) => {
  if (response.status === 401) {
    clearAuth();
    // Redirect trigger for full page reload to clear state and redirect to login
    if (!window.location.pathname.includes('/login')) {
      window.location.href = '/login';
    }
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || 'Session expired. Please log in again.');
  }

  if (!response.ok) {
    const errData = await response.json().catch(() => ({}));
    throw new Error(errData.detail || `API request failed with status ${response.status}`);
  }

  // Handle file downloads
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/pdf')) {
    return response.blob();
  }

  return response.json();
};

export const api = {
  get: async (url) => {
    const token = getAuthToken();
    const headers = {
      'Accept': 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(`${BASE_API_URL}${url}`, { method: 'GET', headers });
    return handleResponse(res);
  },

  post: async (url, body, isMultipart = false) => {
    const token = getAuthToken();
    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    let options = { method: 'POST', headers };
    
    if (isMultipart) {
      // Fetch automatically sets boundary header for FormData, do not set Content-Type manually
      options.body = body;
    } else {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
    
    const res = await fetch(`${BASE_API_URL}${url}`, options);
    return handleResponse(res);
  },

  put: async (url, body) => {
    const token = getAuthToken();
    const headers = {
      'Content-Type': 'application/json',
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(`${BASE_API_URL}${url}`, {
      method: 'PUT',
      headers,
      body: JSON.stringify(body)
    });
    return handleResponse(res);
  },

  delete: async (url) => {
    const token = getAuthToken();
    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const res = await fetch(`${BASE_API_URL}${url}`, { method: 'DELETE', headers });
    return handleResponse(res);
  }
};
