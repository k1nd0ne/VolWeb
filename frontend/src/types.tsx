export interface Case {
  id: number;
  name: string;
  description: string;
  bucket_id: string;
  linked_users: Array<string>;
  last_update: string;
}

export interface User {
  id: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
}

export interface Evidence {
  id: number;
  name: string;
  os: string;
  status: number;
}

export interface CloudStorage {
  endpoint: string;
  access_key: string;
  secret_key: string;
  region: string;
}
