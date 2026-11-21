import { buildApp } from './app.js';
import { config } from './config.js';

const app = await buildApp();

try {
  await app.listen({ host: config.host, port: config.port });
  app.log.info(
    `Pull WHOIS ${config.version} listening on http://${config.host}:${config.port} (auth: ${
      app.adminStore.requireKey ? 'api-key' : 'public'
    }, admin: ${config.admin.password ? 'enabled' : 'disabled'})`,
  );
} catch (error) {
  app.log.error({ err: error }, 'failed to start server');
  process.exit(1);
}

let closing = false;
async function shutdown(signal: string): Promise<void> {
  if (closing) return;
  closing = true;
  app.log.info({ signal }, 'shutting down');
  try {
    await app.adminStore.flush();
    await app.close();
    process.exit(0);
  } catch (error) {
    app.log.error({ err: error }, 'shutdown error');
    process.exit(1);
  }
}

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('unhandledRejection', (reason) => {
  app.log.error({ err: reason }, 'unhandled rejection');
});
