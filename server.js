const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");

const DEFAULT_PORT = 3000;
const PORT = Number.parseInt(process.env.PORT || String(DEFAULT_PORT), 10);
const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8080";
const FRONTEND_ROOT = path.join(__dirname, "frontend");

const CONTENT_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

function sendFile(response, filePath) {
  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === "ENOENT") {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        response.end("Not found");
        return;
      }

      response.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Unable to read file");
      return;
    }

    const extension = path.extname(filePath).toLowerCase();
    response.writeHead(200, {
      "Content-Type": CONTENT_TYPES[extension] || "application/octet-stream",
      "Cache-Control": "no-store"
    });
    response.end(content);
  });
}

function proxyApi(request, response) {
  const targetUrl = new URL(request.url, BACKEND_URL);
  const transport = targetUrl.protocol === "https:" ? https : http;
  const proxyRequest = transport.request(
    {
      protocol: targetUrl.protocol,
      hostname: targetUrl.hostname,
      port: targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80),
      path: `${targetUrl.pathname}${targetUrl.search}`,
      method: request.method,
      headers: {
        ...request.headers,
        host: targetUrl.host
      }
    },
    (proxyResponse) => {
      response.writeHead(proxyResponse.statusCode || 500, proxyResponse.headers);
      proxyResponse.pipe(response);
    }
  );

  proxyRequest.on("error", () => {
    response.writeHead(502, { "Content-Type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ error: "Backend unavailable" }));
  });

  request.pipe(proxyRequest);
}

const server = http.createServer((request, response) => {
  const requestUrl = new URL(request.url, `http://${request.headers.host || "localhost"}`);
  const pathname = requestUrl.pathname;

  if (pathname === "/env.js" || pathname === "/frontend/env.js") {
    response.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-store" });
    const clientId = process.env.GOOGLE_CLIENT_ID || "415741727195-o4f10dgd13hrph7enkmmjge0mtfa2de1.apps.googleusercontent.com";
    response.end(`window.__GOOGLE_CLIENT_ID__ = ${JSON.stringify(clientId)};\n`);
    return;
  }

  if (pathname.startsWith("/api/")) {
    proxyApi(request, response);
    return;
  }

  if (pathname === "/") {
    sendFile(response, path.join(FRONTEND_ROOT, "index.html"));
    return;
  }

  const safePath = pathname.startsWith("/frontend/") ? pathname.slice("/frontend/".length) : pathname.slice(1);
  const filePath = path.resolve(FRONTEND_ROOT, safePath || "index.html");

  if (!filePath.startsWith(FRONTEND_ROOT + path.sep) && filePath !== FRONTEND_ROOT) {
    response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Forbidden");
    return;
  }

  sendFile(response, filePath);
});

function listenOnPreferredPort() {
  server.on("error", (error) => {
    if (error && error.code === "EADDRINUSE") {
      console.error(`Port ${PORT} is already in use. Stop the process using it, then restart the app.`);
      process.exit(1);
    }
    throw error;
  });

  server.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`Library Management System is running at:`);
    console.log(`👉 http://localhost:${PORT}`);
    console.log(`API requests proxied to: ${BACKEND_URL}`);
    console.log(``);
    console.log(`For Google Sign-In in Google Cloud Console:`);
    console.log(`- Authorized JavaScript origins: http://localhost:${PORT}`);
    console.log(`- Authorized redirect URIs:      http://localhost:${PORT}`);
    console.log(`=======================================================`);
  });
}

listenOnPreferredPort();

