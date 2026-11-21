import 'fastify';
import type { AdminStore } from '../admin/store.js';

declare module 'fastify' {
  interface FastifyInstance {
    adminStore: AdminStore;
  }

  interface FastifyRequest {
    rateLimitInfo?: {
      limit: number;
      remaining: number;
      resetMs: number;
    };
    apiKey?: string;
  }
}
