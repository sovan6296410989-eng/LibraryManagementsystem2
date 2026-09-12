import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Small HTTP API for the library application.
 *
 * Authentication deliberately uses short-lived, random bearer tokens kept in
 * memory. Restarting the process invalidates all active sessions.
 */
public class Server {
    private static final Logger LOGGER = Logger.getLogger(Server.class.getName());
    private static final String GOOGLE_CLIENT_ID =
            System.getenv().getOrDefault("GOOGLE_CLIENT_ID",
            "415741727195-o4f10dgd13hrph7enkmmjge0mtfa2de1.apps.googleusercontent.com").trim();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int SESSION_BYTES = 32;
    private static final long SESSION_TTL_MILLIS = Duration.ofHours(8).toMillis();
    private static final int PASSWORD_ITERATIONS = 120_000;
    private static final int PASSWORD_KEY_LENGTH = 256;
    private static final int DEFAULT_PORT = 8080;
    private static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();
    private static final Path FRONTEND_ROOT = Paths.get("frontend").toAbsolutePath().normalize();

    public static void main(String[] args) throws Exception {
        initializeUsersTable();
        bootstrapAdmin();

        int port = Integer.parseInt(System.getenv().getOrDefault("BACKEND_PORT",
                System.getenv().getOrDefault("PORT", String.valueOf(DEFAULT_PORT))));
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
            server.createContext("/api", Server::handleRequest);
            server.createContext("/health", Server::handleRequest);
            server.createContext("/", Server::handleRoot);
            server.setExecutor(null);

            System.out.println("=================================");
            System.out.println("Library Management System Started");
            System.out.println("👉 Access URL: http://localhost:" + port);
            System.out.println("Google OAuth Origin: http://localhost:" + port);
            System.out.println("=================================");
            server.start();
        } catch (java.net.BindException e) {
            throw new IllegalStateException("Port " + port + " is already in use. Stop the process using it, then restart the app.", e);
        }
    }

    private static void handleRoot(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);
        if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 204, "");
            return;
        }

        String path = exchange.getRequestURI().getPath();

        if (path.startsWith("/api/")) {
            handleRequest(exchange);
            return;
        }

        if ("/health".equals(path)) {
            sendResponse(exchange, 200, "{\"status\":\"ok\",\"service\":\"Library Management API\",\"version\":\"1.0.0\"}");
            return;
        }

        if ("/env.js".equals(path) || "/frontend/env.js".equals(path)) {
            byte[] envData = ("window.__GOOGLE_CLIENT_ID__ = \"" + escapeJson(GOOGLE_CLIENT_ID) + "\";\n")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/javascript; charset=UTF-8");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.sendResponseHeaders(200, envData.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(envData);
            }
            return;
        }

        String relative = path.equals("/") || path.equals("/frontend") || path.equals("/frontend/")
                ? "index.html"
                : path.startsWith("/frontend/") ? path.substring("/frontend/".length()) : path.substring(1);

        Path filePath = FRONTEND_ROOT.resolve(relative).normalize();

        if (!filePath.startsWith(FRONTEND_ROOT) || !Files.exists(filePath) || Files.isDirectory(filePath)) {
            sendError(exchange, 404, "Page not found");
            return;
        }

        String contentType = getContentType(filePath.toString());
        byte[] content = Files.readAllBytes(filePath);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, content.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(content);
        }
    }

    private static String getContentType(String filePath) {
        String lower = filePath.toLowerCase();
        if (lower.endsWith(".html")) return "text/html; charset=UTF-8";
        if (lower.endsWith(".css")) return "text/css; charset=UTF-8";
        if (lower.endsWith(".js")) return "application/javascript; charset=UTF-8";
        if (lower.endsWith(".json")) return "application/json; charset=UTF-8";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".ico")) return "image/x-icon";
        return "application/octet-stream";
    }

    private static void handleRequest(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();

        if ("OPTIONS".equalsIgnoreCase(method)) {
            sendResponse(exchange, 204, "");
            return;
        }

        try {
            if (("/api/health".equals(path) || "/health".equals(path)) && "GET".equalsIgnoreCase(method)) {
                sendResponse(exchange, 200, "{\"status\":\"ok\",\"service\":\"Library Management API\",\"timestamp\":" + System.currentTimeMillis() + "}");
                return;
            }
            if ("/api/config".equals(path) && "GET".equalsIgnoreCase(method)) {
                sendResponse(exchange, 200, "{\"googleClientId\":\"" + escapeJson(GOOGLE_CLIENT_ID) + "\",\"version\":\"1.0.0\"}");
                return;
            }
            if ("/api/auth/register".equals(path) && "POST".equalsIgnoreCase(method)) {
                register(exchange);
                return;
            }
            if ("/api/auth/login".equals(path) && "POST".equalsIgnoreCase(method)) {
                login(exchange);
                return;
            }
            if ("/api/auth/google".equals(path) && "POST".equalsIgnoreCase(method)) {
                googleLogin(exchange);
                return;
            }
            if ("/api/auth/logout".equals(path) && "POST".equalsIgnoreCase(method)) {
                if (requireUser(exchange) != null) {
                    SESSIONS.remove(bearerToken(exchange));
                    sendResponse(exchange, 204, "");
                }
                return;
            }
            if ("/api/auth/me".equals(path) && "GET".equalsIgnoreCase(method)) {
                User user = requireUser(exchange);
                if (user != null) {
                    sendResponse(exchange, 200, userJson(user));
                }
                return;
            }

            if ("/api/books".equals(path) && "GET".equalsIgnoreCase(method)) {
                if (requireUser(exchange) != null) {
                    getBooks(exchange);
                }
                return;
            }
            if ("/api/members".equals(path) && "GET".equalsIgnoreCase(method)) {
                if (requireUser(exchange) != null) {
                    getMembers(exchange);
                }
                return;
            }
            if ("/api/books".equals(path) && "POST".equalsIgnoreCase(method)) {
                if (requireAdmin(exchange) != null) {
                    addBook(exchange);
                }
                return;
            }
            if ("/api/members".equals(path) && "POST".equalsIgnoreCase(method)) {
                if (requireAdmin(exchange) != null) {
                    addMember(exchange);
                }
                return;
            }
            if (path.matches("/api/books/[0-9]+/issue") && "PUT".equalsIgnoreCase(method)) {
                User user = requireUser(exchange);
                if (user != null) {
                    if ("ADMIN".equals(user.role)) issueBook(exchange, getIdFromPath(path));
                    else createIssueRequest(exchange, user, getIdFromPath(path));
                }
                return;
            }
            if ("/api/issue-requests".equals(path) && "GET".equalsIgnoreCase(method)) {
                if (requireAdmin(exchange) != null) getIssueRequests(exchange);
                return;
            }
            if (path.matches("/api/issue-requests/[0-9]+/(approve|reject)")
                    && "PUT".equalsIgnoreCase(method)) {
                if (requireAdmin(exchange) != null) {
                    processIssueRequest(exchange, getIdFromPath(path), path.endsWith("/approve"));
                }
                return;
            }
            if (path.matches("/api/books/[0-9]+/return") && "PUT".equalsIgnoreCase(method)) {
                if (requireUser(exchange) != null) {
                    returnBook(exchange, getIdFromPath(path));
                }
                return;
            }
            if (path.matches("/api/books/[0-9]+") && "DELETE".equalsIgnoreCase(method)) {
                if (requireAdmin(exchange) != null) {
                    deleteBook(exchange, getIdFromPath(path));
                }
                return;
            }

            sendError(exchange, 404, "API endpoint not found");
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, e.getMessage());
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Request handling failed", e);
            if (!exchange.getResponseHeaders().containsKey("Content-Type")) {
                sendError(exchange, 500, "Server error");
            }
        }
    }

    private static User requireUser(HttpExchange exchange) throws Exception {
        String token = bearerToken(exchange);
        Session session = token == null ? null : SESSIONS.get(token);
        if (session == null || session.expiresAt < System.currentTimeMillis()) {
            if (token != null) {
                SESSIONS.remove(token);
            }
            sendError(exchange, 401, "Authentication is required");
            return null;
        }
        return session.user;
    }

    private static User requireAdmin(HttpExchange exchange) throws Exception {
        User user = requireUser(exchange);
        if (user != null && !"ADMIN".equals(user.role)) {
            sendError(exchange, 403, "Administrator privileges are required");
            return null;
        }
        return user;
    }

    private static String bearerToken(HttpExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = header.substring(7).trim();
        return token.isEmpty() ? null : token;
    }

    private static void register(HttpExchange exchange) throws Exception {
        String body = readRequestBody(exchange);
        String name = requiredJson(body, "name", "Name is required").trim();
        String email = requiredJson(body, "email", "Email is required").trim().toLowerCase();
        String password = requiredJson(body, "password", "Password is required");

        if (name.length() > 120 || name.isEmpty()) {
            sendError(exchange, 400, "Name must be between 1 and 120 characters");
            return;
        }
        if (!email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) {
            sendError(exchange, 400, "A valid email address is required");
            return;
        }
        if (password.length() < 6 || password.length() > 200) {
            sendError(exchange, 400, "Password must be between 6 and 200 characters");
            return;
        }

        try (Connection con = dbconnection.getConnection();
             PreparedStatement ps = con.prepareStatement(
                     "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'USER')")) {
            ps.setString(1, name);
            ps.setString(2, email);
            ps.setString(3, hashPassword(password));
            ps.executeUpdate();
        } catch (SQLException e) {
            if (e.getErrorCode() == 1062 || e.getMessage().toLowerCase().contains("duplicate")) {
                sendError(exchange, 409, "An account with that email already exists");
                return;
            }
            throw e;
        }

        User user = findUser(email);
        sendAuthResponse(exchange, 201, user);
    }

    private static void login(HttpExchange exchange) throws Exception {
        String body = readRequestBody(exchange);
        String email = requiredJson(body, "email", "Email is required").trim().toLowerCase();
        String password = requiredJson(body, "password", "Password is required");
        User user = findUser(email);

        if (user == null || !verifyPassword(password, user.passwordHash)) {
            sendError(exchange, 401, "Invalid email or password");
            return;
        }
        sendAuthResponse(exchange, 200, user);
    }

    private static void googleLogin(HttpExchange exchange) throws Exception {
        String body = readRequestBody(exchange);
        String credential = requiredJson(body, "credential", "Google credential is required");
        String tokenInfo = verifyGoogleCredential(credential);
        String audience = getJsonValue(tokenInfo, "aud");
        String azp = getJsonValue(tokenInfo, "azp");
        String email = requiredJson(tokenInfo, "email", "Google email is missing").trim().toLowerCase();
        String verified = getJsonValue(tokenInfo, "email_verified");

        boolean audienceMatches = GOOGLE_CLIENT_ID.equals(audience) || GOOGLE_CLIENT_ID.equals(azp);
        boolean isVerified = "true".equalsIgnoreCase(verified);
        if (!audienceMatches || !isVerified) {
            LOGGER.warning("Google verification mismatch. aud=" + audience + ", azp=" + azp + ", expected=" + GOOGLE_CLIENT_ID);
            sendError(exchange, 401, "Google account verification failed");
            return;
        }

        User user = findUser(email);
        if (user == null) {
            String name = getJsonValue(tokenInfo, "name");
            if (name == null || name.trim().isEmpty()) name = email;
            try (Connection con = dbconnection.getConnection();
                 PreparedStatement ps = con.prepareStatement(
                         "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'USER')")) {
                byte[] randomPassword = new byte[32];
                RANDOM.nextBytes(randomPassword);
                ps.setString(1, name.trim());
                ps.setString(2, email);
                ps.setString(3, hashPassword(Base64.getUrlEncoder().encodeToString(randomPassword)));
                ps.executeUpdate();
            }
            user = findUser(email);
        }
        sendAuthResponse(exchange, 200, user);
    }

    private static String verifyGoogleCredential(String credential) throws Exception {
        URL url = URI.create("https://oauth2.googleapis.com/tokeninfo?id_token="
            + java.net.URLEncoder.encode(credential, StandardCharsets.UTF_8)).toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        int status = connection.getResponseCode();
        try (InputStream input = status >= 200 && status < 300
                ? connection.getInputStream() : connection.getErrorStream()) {
            String response = input == null ? "" : new String(input.readAllBytes(), StandardCharsets.UTF_8);
            if (status < 200 || status >= 300) {
                throw new IllegalArgumentException("Google account verification failed");
            }
            return response;
        } finally {
            connection.disconnect();
        }
    }

    private static void sendAuthResponse(HttpExchange exchange, int status, User user)
            throws IOException {
        String token = createSession(user);
        sendResponse(exchange, status, "{\"token\":\"" + escapeJson(token)
                + "\",\"user\":" + userJson(user) + "}");
    }

    private static String createSession(User user) {
        byte[] bytes = new byte[SESSION_BYTES];
        RANDOM.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        SESSIONS.put(token, new Session(user, System.currentTimeMillis() + SESSION_TTL_MILLIS));
        return token;
    }

    private static User findUser(String email) throws Exception {
        try (Connection con = dbconnection.getConnection();
             PreparedStatement ps = con.prepareStatement(
                     "SELECT id, name, email, password_hash, role FROM users WHERE email = ?")) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new User(rs.getInt("id"), rs.getString("name"), rs.getString("email"),
                            rs.getString("password_hash"), rs.getString("role"));
                }
            }
        }
        return null;
    }

    private static void initializeUsersTable() throws Exception {
        try (Connection con = dbconnection.getConnection();
             Statement statement = con.createStatement()) {
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS books ("
                    + "book_id INT NOT NULL PRIMARY KEY,"
                    + "title VARCHAR(255) NOT NULL,"
                    + "author VARCHAR(255) NOT NULL,"
                    + "available BOOLEAN NOT NULL DEFAULT TRUE)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS members ("
                    + "member_id INT NOT NULL PRIMARY KEY,"
                    + "name VARCHAR(120) NOT NULL)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS issue_requests ("
                    + "request_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
                    + "user_id INT NOT NULL,"
                    + "book_id INT NOT NULL,"
                    + "status VARCHAR(10) NOT NULL DEFAULT 'PENDING',"
                    + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)");
            statement.executeUpdate("CREATE TABLE IF NOT EXISTS users ("
                    + "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
                    + "name VARCHAR(120) NOT NULL,"
                    + "email VARCHAR(255) NOT NULL UNIQUE,"
                    + "password_hash VARCHAR(512) NOT NULL,"
                    + "role VARCHAR(10) NOT NULL DEFAULT 'USER',"
                    + "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                    + "INDEX idx_users_email (email))");
        }
    }

    private static void bootstrapAdmin() throws Exception {
        String email = System.getenv("ADMIN_EMAIL");
        String password = System.getenv("ADMIN_PASSWORD");
        if (email == null || password == null || email.trim().isEmpty() || password.isEmpty()) {
            System.out.println("ADMIN_EMAIL/ADMIN_PASSWORD not set; no admin bootstrap was requested.");
            return;
        }
        email = email.trim().toLowerCase();
        User existing = findUser(email);
        if (existing == null) {
            try (Connection con = dbconnection.getConnection();
                 PreparedStatement ps = con.prepareStatement(
                         "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'ADMIN')")) {
                ps.setString(1, "Library Administrator");
                ps.setString(2, email);
                ps.setString(3, hashPassword(password));
                ps.executeUpdate();
            }
            System.out.println("Bootstrap administrator created for " + email);
        } else if (!"ADMIN".equals(existing.role)) {
            try (Connection con = dbconnection.getConnection();
                 PreparedStatement ps = con.prepareStatement(
                         "UPDATE users SET role = 'ADMIN' WHERE email = ?")) {
                ps.setString(1, email);
                ps.executeUpdate();
            }
            System.out.println("Bootstrap administrator role granted to " + email);
        }
    }

    private static String hashPassword(String password) throws Exception {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        byte[] hash = pbkdf2(password.toCharArray(), salt, PASSWORD_ITERATIONS);
        return PASSWORD_ITERATIONS + "$" + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(hash);
    }

    private static boolean verifyPassword(String password, String stored) throws Exception {
        String[] parts = stored.split("\\$", -1);
        if (parts.length != 3) {
            return false;
        }
        int iterations = Integer.parseInt(parts[0]);
        byte[] salt = Base64.getDecoder().decode(parts[1]);
        byte[] expected = Base64.getDecoder().decode(parts[2]);
        byte[] actual = pbkdf2(password.toCharArray(), salt, iterations);
        return MessageDigest.isEqual(expected, actual);
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, iterations, PASSWORD_KEY_LENGTH);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    private static void getBooks(HttpExchange exchange) throws Exception {
        try (Connection con = dbconnection.getConnection();
             PreparedStatement ps = con.prepareStatement(
                     "SELECT book_id, title, author, available FROM books ORDER BY book_id");
             ResultSet rs = ps.executeQuery()) {
            StringBuilder json = new StringBuilder("[");
            while (rs.next()) {
                if (json.length() > 1) json.append(',');
                json.append("{\"bookId\":").append(rs.getInt("book_id"))
                        .append(",\"title\":\"").append(escapeJson(rs.getString("title")))
                        .append("\",\"author\":\"").append(escapeJson(rs.getString("author")))
                        .append("\",\"available\":").append(rs.getBoolean("available")).append('}');
            }
            sendResponse(exchange, 200, json.append(']').toString());
        }
    }

    private static void addBook(HttpExchange exchange) throws Exception {
        String body = readRequestBody(exchange);
        String title = requiredJson(body, "title", "Book title is required").trim();
        String author = requiredJson(body, "author", "Author is required").trim();
        if (title.isEmpty() || author.isEmpty()) {
            sendError(exchange, 400, "Book title and author are required");
            return;
        }
        String requestedId = getJsonValue(body, "bookId");
        try (Connection con = dbconnection.getConnection()) {
            int bookId = requestedId == null || requestedId.trim().isEmpty()
                    ? getNextBookId(con) : positiveInt(requestedId, "Book ID");
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO books (book_id, title, author, available) VALUES (?, ?, ?, TRUE)")) {
                ps.setInt(1, bookId);
                ps.setString(2, title);
                ps.setString(3, author);
                ps.executeUpdate();
            } catch (SQLException e) {
                if (e.getErrorCode() == 1062) {
                    sendError(exchange, 409, "Book ID is already in use");
                    return;
                }
                throw e;
            }
            sendResponse(exchange, 201, "{\"message\":\"Book added successfully\",\"bookId\":" + bookId + "}");
        }
    }

    private static void getMembers(HttpExchange exchange) throws Exception {
        try (Connection con = dbconnection.getConnection();
             PreparedStatement ps = con.prepareStatement(
                     "SELECT member_id, name FROM members ORDER BY member_id");
             ResultSet rs = ps.executeQuery()) {
            StringBuilder json = new StringBuilder("[");
            while (rs.next()) {
                if (json.length() > 1) json.append(',');
                json.append("{\"memberId\":").append(rs.getInt("member_id"))
                        .append(",\"name\":\"").append(escapeJson(rs.getString("name"))).append("\"}");
            }
            sendResponse(exchange, 200, json.append(']').toString());
        }
    }

    private static void addMember(HttpExchange exchange) throws Exception {
        String name = requiredJson(readRequestBody(exchange), "name", "Member name is required").trim();
        if (name.isEmpty()) {
            sendError(exchange, 400, "Member name is required");
            return;
        }
        try (Connection con = dbconnection.getConnection();
             PreparedStatement ps = con.prepareStatement(
                     "INSERT INTO members (member_id, name) VALUES (?, ?)")) {
            int memberId = getNextMemberId(con);
            ps.setInt(1, memberId);
            ps.setString(2, name);
            ps.executeUpdate();
            sendResponse(exchange, 201, "{\"message\":\"Member added successfully\",\"memberId\":" + memberId + "}");
        }
    }

    private static void issueBook(HttpExchange exchange, int bookId) throws Exception {
        changeBookAvailability(exchange, bookId, false, "issued", "already issued");
    }

    private static void createIssueRequest(HttpExchange exchange, User user, int bookId) throws Exception {
        try (Connection con = dbconnection.getConnection();
             PreparedStatement book = con.prepareStatement("SELECT available FROM books WHERE book_id = ?");
             PreparedStatement pending = con.prepareStatement(
                     "SELECT request_id FROM issue_requests WHERE user_id = ? AND book_id = ? AND status = 'PENDING'")) {
            book.setInt(1, bookId);
            try (ResultSet rs = book.executeQuery()) {
                if (!rs.next()) { sendError(exchange, 404, "Book not found"); return; }
                if (!rs.getBoolean("available")) { sendError(exchange, 400, "Book is already issued"); return; }
            }
            pending.setInt(1, user.id);
            pending.setInt(2, bookId);
            try (ResultSet rs = pending.executeQuery()) {
                if (rs.next()) { sendError(exchange, 409, "An issue request is already pending"); return; }
            }
        }
        try (Connection con = dbconnection.getConnection();
             PreparedStatement ps = con.prepareStatement(
                     "INSERT INTO issue_requests (user_id, book_id) VALUES (?, ?)",
                     Statement.RETURN_GENERATED_KEYS)) {
            ps.setInt(1, user.id);
            ps.setInt(2, bookId);
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                int requestId = keys.next() ? keys.getInt(1) : 0;
                sendResponse(exchange, 202, "{\"message\":\"Issue request sent to administrator\",\"requestId\":"
                        + requestId + "}");
            }
        }
    }

    private static void getIssueRequests(HttpExchange exchange) throws Exception {
        try (Connection con = dbconnection.getConnection();
             PreparedStatement ps = con.prepareStatement(
                     "SELECT r.request_id, r.book_id, b.title, u.name, u.email, r.status "
                     + "FROM issue_requests r JOIN users u ON u.id = r.user_id "
                     + "JOIN books b ON b.book_id = r.book_id WHERE r.status = 'PENDING' "
                     + "ORDER BY r.created_at");
             ResultSet rs = ps.executeQuery()) {
            StringBuilder json = new StringBuilder("[");
            while (rs.next()) {
                if (json.length() > 1) json.append(',');
                json.append("{\"requestId\":").append(rs.getInt("request_id"))
                        .append(",\"bookId\":").append(rs.getInt("book_id"))
                        .append(",\"title\":\"").append(escapeJson(rs.getString("title")))
                        .append("\",\"userName\":\"").append(escapeJson(rs.getString("name")))
                        .append("\",\"email\":\"").append(escapeJson(rs.getString("email")))
                        .append("\",\"status\":\"").append(rs.getString("status")).append("\"}");
            }
            sendResponse(exchange, 200, json.append(']').toString());
        }
    }

    private static void processIssueRequest(HttpExchange exchange, int requestId, boolean approve)
            throws Exception {
        try (Connection con = dbconnection.getConnection()) {
            con.setAutoCommit(false);
            try (PreparedStatement find = con.prepareStatement(
                    "SELECT book_id FROM issue_requests WHERE request_id = ? AND status = 'PENDING'")) {
                find.setInt(1, requestId);
                try (ResultSet rs = find.executeQuery()) {
                    if (!rs.next()) { sendError(exchange, 404, "Pending issue request not found"); return; }
                    int bookId = rs.getInt("book_id");
                    if (approve) {
                        try (PreparedStatement updateBook = con.prepareStatement(
                                "UPDATE books SET available = FALSE WHERE book_id = ? AND available = TRUE")) {
                            updateBook.setInt(1, bookId);
                            if (updateBook.executeUpdate() == 0) {
                                con.rollback();
                                sendError(exchange, 409, "Book is no longer available");
                                return;
                            }
                        }
                    }
                    try (PreparedStatement update = con.prepareStatement(
                            "UPDATE issue_requests SET status = ? WHERE request_id = ?")) {
                        update.setString(1, approve ? "APPROVED" : "REJECTED");
                        update.setInt(2, requestId);
                        update.executeUpdate();
                    }
                    con.commit();
                    sendResponse(exchange, 200, "{\"message\":\"Issue request "
                            + (approve ? "approved\"}" : "rejected\"}"));
                }
            } catch (Exception e) {
                con.rollback();
                throw e;
            } finally {
                con.setAutoCommit(true);
            }
        }
    }

    private static void returnBook(HttpExchange exchange, int bookId) throws Exception {
        changeBookAvailability(exchange, bookId, true, "returned", "not currently issued");
    }

    private static void deleteBook(HttpExchange exchange, int bookId) throws Exception {
        try (Connection con = dbconnection.getConnection();
             PreparedStatement delete = con.prepareStatement(
                     "DELETE FROM books WHERE book_id = ?")) {
            delete.setInt(1, bookId);
            if (delete.executeUpdate() == 0) {
                sendError(exchange, 404, "Book not found");
                return;
            }
            sendResponse(exchange, 200, "{\"message\":\"Book deleted successfully\"}");
        }
    }

    private static void changeBookAvailability(HttpExchange exchange, int bookId, boolean available,
                                               String action, String conflict) throws Exception {
        try (Connection con = dbconnection.getConnection();
             PreparedStatement update = con.prepareStatement(
                     "UPDATE books SET available = ? WHERE book_id = ? AND available = ?")) {
            update.setBoolean(1, available);
            update.setInt(2, bookId);
            update.setBoolean(3, !available);
            if (update.executeUpdate() == 0) {
                try (PreparedStatement check = con.prepareStatement(
                        "SELECT available FROM books WHERE book_id = ?")) {
                    check.setInt(1, bookId);
                    try (ResultSet rs = check.executeQuery()) {
                        if (!rs.next()) {
                            sendError(exchange, 404, "Book not found");
                        } else {
                            sendError(exchange, 400, "Book is " + conflict);
                        }
                    }
                }
                return;
            }
            sendResponse(exchange, 200, "{\"message\":\"Book " + action + " successfully\"}");
        }
    }

    private static int getNextBookId(Connection con) throws Exception {
        return nextId(con, "books", "book_id");
    }

    private static int getNextMemberId(Connection con) throws Exception {
        return nextId(con, "members", "member_id");
    }

    private static int nextId(Connection con, String table, String column) throws Exception {
        try (PreparedStatement ps = con.prepareStatement(
                "SELECT COALESCE(MAX(" + column + "), 0) + 1 AS next_id FROM " + table);
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getInt("next_id") : 1;
        }
    }

    private static int getIdFromPath(String path) {
        return Integer.parseInt(path.split("/")[3]);
    }

    private static int positiveInt(String value, String label) {
        try {
            int result = Integer.parseInt(value.trim());
            if (result <= 0) throw new NumberFormatException();
            return result;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(label + " must be a positive whole number");
        }
    }

    private static String requiredJson(String json, String key, String message) {
        String value = getJsonValue(json, key);
        if (value == null || value.trim().isEmpty()) throw new IllegalArgumentException(message);
        return value;
    }

    private static String readRequestBody(HttpExchange exchange) throws IOException {
        try (InputStream input = exchange.getRequestBody()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * This parser is intentionally limited to the flat request objects used by
     * this application; all values still go through prepared SQL statements.
     */
    private static String getJsonValue(String json, String key) {
        if (json == null) return null;
        int keyIndex = json.indexOf("\"" + key + "\"");
        if (keyIndex < 0) return null;
        int colon = json.indexOf(':', keyIndex);
        if (colon < 0) return null;
        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (start >= json.length()) return null;
        if (json.charAt(start) == '"') {
            StringBuilder value = new StringBuilder();
            boolean escaped = false;
            for (int i = start + 1; i < json.length(); i++) {
                char c = json.charAt(i);
                if (escaped) {
                    value.append(c == 'n' ? '\n' : c == 'r' ? '\r' : c == 't' ? '\t' : c);
                    escaped = false;
                } else if (c == '\\') {
                    escaped = true;
                } else if (c == '"') {
                    return value.toString();
                } else {
                    value.append(c);
                }
            }
            return null;
        }
        int end = json.indexOf(',', start);
        int objectEnd = json.indexOf('}', start);
        if (end < 0 || (objectEnd >= 0 && objectEnd < end)) end = objectEnd;
        return (end < 0 ? json.substring(start) : json.substring(start, end)).trim();
    }

    private static String userJson(User user) {
        return "{\"id\":" + user.id + ",\"name\":\"" + escapeJson(user.name)
                + "\",\"email\":\"" + escapeJson(user.email) + "\",\"role\":\""
                + escapeJson(user.role) + "\"}";
    }

    private static String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

    private static void sendError(HttpExchange exchange, int status, String message) throws IOException {
        sendResponse(exchange, status, "{\"error\":\"" + escapeJson(message) + "\"}");
    }

    private static void sendResponse(HttpExchange exchange, int status, String response) throws IOException {
        byte[] data = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(status, data.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(data);
        }
    }

    private static final class User {
        final int id;
        final String name;
        final String email;
        final String passwordHash;
        final String role;

        User(int id, String name, String email, String passwordHash, String role) {
            this.id = id;
            this.name = name;
            this.email = email;
            this.passwordHash = passwordHash;
            this.role = role;
        }
    }

    private static final class Session {
        final User user;
        final long expiresAt;

        Session(User user, long expiresAt) {
            this.user = user;
            this.expiresAt = expiresAt;
        }
    }
}
