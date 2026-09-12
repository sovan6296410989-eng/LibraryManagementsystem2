const http = require("http");
const fs = require("fs");
const path = require("path");

const rootDirectory = path.join(__dirname, "frontend");
const port = Number.parseInt(process.env.FRONTEND_PORT || "5500", 10);
const contentTypes = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8"
};

const server = http.createServer((request, response) => {
    const requestPath = decodeURIComponent(request.url.split("?")[0]);
    const relativePath = requestPath === "/" || requestPath === "/frontend/index.html"
        ? "index.html"
        : requestPath.startsWith("/frontend/")
            ? requestPath.slice("/frontend/".length)
            : requestPath.slice(1);
    const filePath = path.resolve(rootDirectory, relativePath);

    if (!filePath.startsWith(rootDirectory + path.sep)) {
        response.writeHead(403);
        response.end("Forbidden");
        return;
    }

    fs.readFile(filePath, (error, content) => {
        if (error) {
            response.writeHead(error.code === "ENOENT" ? 404 : 500);
            response.end(error.code === "ENOENT" ? "Not found" : "Unable to read file");
            return;
        }

        response.writeHead(200, {
            "Content-Type": contentTypes[path.extname(filePath)] || "application/octet-stream",
            "Cache-Control": "no-store"
        });
        response.end(content);
    });
});

server.listen(port, () => {
    console.log(`Frontend running at http://localhost:${port}`);
});
