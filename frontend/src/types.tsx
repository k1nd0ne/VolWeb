export interface Case {
  id: number;
  bucket_id: string;
  name: string;
  description: string;
  linked_users: number[];
  last_update: string;
}