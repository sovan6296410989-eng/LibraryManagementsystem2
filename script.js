const API_BASE_URLS = (() => {
    const configured = typeof window !== "undefined" && window.__API_BASE_URL__
        ? window.__API_BASE_URL__
        : "";
    const candidates = configured ? [configured.replace(/\/$/, "")] : ["http://localhost:8080/api", "/api"];
    return [...new Set(candidates)];
})();

const GOOGLE_CLIENT_ID = "415741727195-o4f10dgd13hrph7enkmmjge0mtfa2de1.apps.googleusercontent.com";

function authToken() {
    return localStorage.getItem("authToken");
}

async function apiRequest(path, options = {}) {
    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {})
    };
    if (authToken() && !headers.Authorization) {
        headers.Authorization = `Bearer ${authToken()}`;
    }

    let lastError = null;
    for (const baseUrl of API_BASE_URLS) {
        try {
            const response = await fetch(`${baseUrl}${path}`, { ...options, headers });
            const body = await response.json().catch(() => ({}));
            if (response.status === 401 && !path.startsWith("/auth/")) {
                clearAuth();
                window.location.href = "index.html";
            }
            if (!response.ok) {
                if (response.status === 404 && baseUrl !== "/api") {
                    continue;
                }
                throw new Error(body.error || "The server could not complete the request.");
            }
            return body;
        } catch (error) {
            lastError = error;
            const message = String(error && error.message ? error.message : error);
            const isConnectionIssue = message.includes("Failed to fetch") || message.includes("fetch") || message.includes("network") || message.includes("not running");
            if (!isConnectionIssue) {
                throw error;
            }
        }
    }

    throw new Error(
        "The library server is not running. Start the Java backend and try again."
    );
}

function showApiError(error) {
    console.error(error);
    alert(error.message || "Unable to connect to the library server.");
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function showSignup() {
    document.getElementById("signinForm").classList.add("hidden");
    document.getElementById("signupForm").classList.remove("hidden");
    document.getElementById("authTitle").textContent = "Create Account";
    document.getElementById("authSubtitle").textContent = "Create your library account";
    document.getElementById("authMessage").textContent = "";
}

function showSignin() {
    document.getElementById("signupForm").classList.add("hidden");
    document.getElementById("signinForm").classList.remove("hidden");
    document.getElementById("authTitle").textContent = "Welcome Back";
    document.getElementById("authSubtitle").textContent = "Sign in to continue to your library";
    document.getElementById("authMessage").textContent = "";
}

function selectLoginType(button) {
    document.querySelectorAll(".login-type-btn").forEach(option => {
        option.classList.toggle("active", option === button);
    });
    document.getElementById("authTitle").textContent =
        button.dataset.loginRole === "ADMIN" ? "Admin Login" : "User Login";
    document.getElementById("authSubtitle").textContent =
        button.dataset.loginRole === "ADMIN"
            ? "Sign in to manage your library"
            : "Sign in to access your library";
    document.getElementById("authMessage").textContent = "";
}

function togglePassword(inputId, button) {
    const input = document.getElementById(inputId);
    input.type = input.type === "password" ? "text" : "password";
    button.textContent = input.type === "password" ? "👁" : "🙈";
}

function forgotPassword(event) {
    event.preventDefault();
    const message = document.getElementById("authMessage");
    message.textContent = "Please contact the administrator to reset your password.";
    message.className = "auth-message success";
}

function saveAuth(result) {
    localStorage.setItem("authToken", result.token);
    localStorage.setItem("userRole", result.user.role);
    localStorage.setItem("userEmail", result.user.email);
    localStorage.setItem("userName", result.user.name);
    localStorage.setItem("isLoggedIn", "true");
}

function handleGoogleCredential(response) {
    const message = document.getElementById("authMessage");
    const selectedLogin = document.querySelector(".login-type-btn.active");
    const selectedRole = selectedLogin ? selectedLogin.dataset.loginRole : "USER";
    apiRequest("/auth/google", {
        method: "POST",
        body: JSON.stringify({ credential: response.credential })
    }).then(result => {
        if (result.user.role !== selectedRole) {
            clearAuth();
            throw new Error(`This account is not an ${selectedRole === "ADMIN" ? "administrator" : "user"} account.`);
        }
        saveAuth(result);
        redirectByRole();
    }).catch(error => {
        message.textContent = error.message;
        message.className = "auth-message error";
    });
}

function initializeGoogleLogin() {
    if (!window.google || !window.google.accounts || !window.google.accounts.id) return;
    window.google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: handleGoogleCredential
    });
    ["googleLoginButton", "googleSignupButton"].forEach(id => {
        const container = document.getElementById(id);
        if (container) {
            window.google.accounts.id.renderButton(container, {
                theme: "outline",
                size: "large",
                width: 360,
                text: "continue_with"
            });
        }
    });
}

function clearAuth() {
    ["authToken", "userRole", "userEmail", "userName", "isLoggedIn"].forEach(key => {
        localStorage.removeItem(key);
    });
}

function redirectByRole() {
    window.location.href = localStorage.getItem("userRole") === "ADMIN"
        ? "dashboard.html" : "user-dashboard.html";
}

function initializeAuthentication() {
    const loginForm = document.getElementById("loginForm");
    const registerForm = document.getElementById("registerForm");
    document.querySelectorAll(".login-type-btn").forEach(button => {
        button.addEventListener("click", () => selectLoginType(button));
    });

    if (loginForm) {
        loginForm.addEventListener("submit", async function(event) {
            event.preventDefault();
            const message = document.getElementById("authMessage");
            const selectedRole = document.querySelector(".login-type-btn.active").dataset.loginRole;
            try {
                const result = await apiRequest("/auth/login", {
                    method: "POST",
                    body: JSON.stringify({
                        email: document.getElementById("loginEmail").value.trim(),
                        password: document.getElementById("loginPassword").value
                    })
                });
                if (result.user.role !== selectedRole) {
                    throw new Error(`This account is not an ${selectedRole === "ADMIN" ? "administrator" : "user"} account.`);
                }
                saveAuth(result);
                redirectByRole();
            } catch (error) {
                message.textContent = error.message;
                message.className = "auth-message error";
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener("submit", async function(event) {
            event.preventDefault();
            const message = document.getElementById("authMessage");
            const password = document.getElementById("signupPassword").value;
            if (password !== document.getElementById("confirmPassword").value) {
                message.textContent = "Passwords do not match.";
                message.className = "auth-message error";
                return;
            }
            try {
                const result = await apiRequest("/auth/register", {
                    method: "POST",
                    body: JSON.stringify({
                        name: document.getElementById("signupName").value.trim(),
                        email: document.getElementById("signupEmail").value.trim(),
                        password
                    })
                });
                saveAuth(result);
                redirectByRole();
            } catch (error) {
                message.textContent = error.message;
                message.className = "auth-message error";
            }
        });
    }
}

function renderBooks(books) {
    const table = document.getElementById("bookTableBody");
    const userTable = document.getElementById("userBookTableBody");
    const overview = document.getElementById("dashboardBookTableBody");
    const admin = localStorage.getItem("userRole") === "ADMIN";
    const rows = books.map(book => `
        <tr data-book="${book.bookId} ${escapeHtml(book.title)} ${escapeHtml(book.author)}">
            <td>${book.bookId}</td>
            <td>${escapeHtml(book.title)}</td>
            <td>${escapeHtml(book.author)}</td>
            <td><span class="${book.available ? "status-available" : "status-issued"}">${book.available ? "Available" : "Issued"}</span></td>
            ${admin
                ? `<td>${book.available
                    ? `<button class="success-btn table-btn" onclick="issueBook(${book.bookId})">Issue</button>`
                    : `<button class="primary-btn table-btn" onclick="returnBook(${book.bookId})">Return</button>`}
                    <button class="danger-btn table-btn" onclick="deleteBook(${book.bookId})">Delete</button></td>`
                : `<td>${book.available
                    ? `<button class="success-btn table-btn" onclick="issueBook(${book.bookId})">Issue Book</button>`
                    : `<button class="primary-btn table-btn" onclick="returnBook(${book.bookId})">Return Book</button>`}</td>`}
        </tr>
    `).join("");

    if (table) table.innerHTML = rows || '<tr><td colspan="5">No books found.</td></tr>';
    if (userTable) userTable.innerHTML = rows || '<tr><td colspan="5">No books found.</td></tr>';
    if (overview) {
        overview.innerHTML = books.length ? books.slice(0, 5).map(book => `
            <tr><td>${book.bookId}</td><td>${escapeHtml(book.title)}</td>
            <td>${escapeHtml(book.author)}</td><td><span class="${book.available ? "status-available" : "status-issued"}">
            ${book.available ? "Available" : "Issued"}</span></td></tr>`).join("")
            : '<tr><td colspan="4">No books found.</td></tr>';
    }
}

function renderMembers(members) {
    const targets = ["memberTableBody", "userMemberTableBody"];
    targets.forEach(id => {
        const table = document.getElementById(id);
        if (table) {
            table.innerHTML = members.length
                ? members.map(member => `<tr><td>${member.memberId}</td><td>${escapeHtml(member.name)}</td></tr>`).join("")
                : '<tr><td colspan="2">No members found.</td></tr>';
        }
    });
}

async function loadLibraryData() {
    try {
        const books = await apiRequest("/books");
        renderBooks(books);
        const values = {
            totalBooks: books.length,
            availableBooks: books.filter(book => book.available).length,
            issuedBooks: books.filter(book => !book.available).length
        };
        Object.keys(values).forEach(id => {
            const element = document.getElementById(id);
            if (element) element.textContent = values[id];
        });
    } catch (error) {
        console.error("Unable to load books:", error);
        const table = document.getElementById("userBookTableBody") || document.getElementById("bookTableBody");
        if (table) table.innerHTML = `<tr><td colspan="5">${escapeHtml(error.message)}</td></tr>`;
    }
    if (document.getElementById("memberTableBody")) {
        await loadMembers();
    }
}

async function loadMembers() {
    try {
        const members = await apiRequest("/members");
        renderMembers(members);
        const totalMembers = document.getElementById("totalMembers");
        if (totalMembers) totalMembers.textContent = members.length;
    } catch (error) {
        console.error("Unable to load members:", error);
        const table = document.getElementById("memberTableBody");
        if (table) table.innerHTML = `<tr><td colspan="2">${escapeHtml(error.message)}</td></tr>`;
    }
}

function showSection(sectionId) {
    document.querySelectorAll(".content-section").forEach(section => {
        section.classList.toggle("active", section.id === sectionId);
    });
    document.querySelectorAll(".nav-link").forEach(link => {
        link.classList.toggle("active", link.dataset.section === sectionId);
    });
    if (sectionId === "members") {
        loadMembers();
    }
    if (sectionId === "requests") {
        loadIssueRequests();
    }
}

function openUserCatalogue() {
    const catalogue = document.getElementById("userDashboard");
    if (!catalogue) return;
    document.querySelectorAll(".user-nav-button").forEach(button => {
        button.classList.toggle("active", button.textContent.includes("Catalogue"));
    });
    catalogue.scrollIntoView({ behavior: "smooth", block: "start" });
}

function searchBooks() {
    const input = document.getElementById("bookSearch");
    if (!input) return;
    const query = input.value.toLowerCase().trim();
    document.querySelectorAll("#bookTableBody tr").forEach(row => {
        row.hidden = query !== "" && !(row.dataset.book || "").toLowerCase().includes(query);
    });
}

function openBookModal() { document.getElementById("bookModal").classList.add("show"); }
function closeBookModal() { document.getElementById("bookModal").classList.remove("show"); }
function openMemberModal() { document.getElementById("memberModal").classList.add("show"); }
function closeMemberModal() { document.getElementById("memberModal").classList.remove("show"); }

async function addBook() {
    const bookId = document.getElementById("bookId").value.trim();
    const title = document.getElementById("bookTitle").value.trim();
    const author = document.getElementById("bookAuthor").value.trim();
    if (bookId && !/^[1-9]\d*$/.test(bookId)) return alert("Book ID must be a positive whole number.");
    if (!title || !author) return alert("Book title and author are required.");
    try {
        const book = { title, author };
        if (bookId) book.bookId = Number(bookId);
        await apiRequest("/books", { method: "POST", body: JSON.stringify(book) });
        document.getElementById("bookId").value = "";
        document.getElementById("bookTitle").value = "";
        document.getElementById("bookAuthor").value = "";
        closeBookModal();
        await loadLibraryData();
    } catch (error) { showApiError(error); }
}

async function addMember() {
    const name = document.getElementById("memberName").value.trim();
    if (!name) return alert("Member name is required.");
    try {
        await apiRequest("/members", { method: "POST", body: JSON.stringify({ name }) });
        document.getElementById("memberName").value = "";
        closeMemberModal();
        await loadLibraryData();
    } catch (error) { showApiError(error); }
}

async function deleteBook(bookId) {
    if (!window.confirm(`Delete book ${bookId}? This cannot be undone.`)) {
        return;
    }

    try {
        await apiRequest(`/books/${bookId}`, { method: "DELETE" });
        await loadLibraryData();
    } catch (error) {
        showApiError(error);
    }
}

async function updateBookStatus(bookId, action) {
    await apiRequest(`/books/${bookId}/${action}`, { method: "PUT" });
    await loadLibraryData();
}

async function loadIssueRequests() {
    const table = document.getElementById("issueRequestsTableBody");
    if (!table) return;
    try {
        const requests = await apiRequest("/issue-requests");
        table.innerHTML = requests.length
            ? requests.map(request => `<tr>
                <td>${request.requestId}</td>
                <td>${request.bookId} - ${escapeHtml(request.title)}</td>
                <td>${escapeHtml(request.userName)}</td>
                <td>${escapeHtml(request.email)}</td>
                <td>
                    <button class="success-btn table-btn" onclick="processIssueRequest(${request.requestId}, 'approve')">Approve</button>
                    <button class="danger-btn table-btn" onclick="processIssueRequest(${request.requestId}, 'reject')">Reject</button>
                </td>
            </tr>`).join("")
            : '<tr><td colspan="5">No pending issue requests.</td></tr>';
    } catch (error) {
        table.innerHTML = `<tr><td colspan="5">${escapeHtml(error.message)}</td></tr>`;
    }
}

async function processIssueRequest(requestId, action) {
    try {
        await apiRequest(`/issue-requests/${requestId}/${action}`, { method: "PUT" });
        await loadIssueRequests();
        await loadLibraryData();
    } catch (error) {
        showApiError(error);
    }
}

async function issueBook(bookId) {
    const input = document.getElementById("issueBookId");
    const rawId = bookId === undefined
        ? input.value.trim()
        : window.prompt("Enter the Issue ID (Book ID) to issue:", String(bookId));
    if (rawId === null) return;
    if (!/^[1-9]\d*$/.test(rawId)) return alert("Enter a valid Book ID.");
    try {
        const response = await apiRequest(`/books/${Number(rawId)}/issue`, { method: "PUT" });
        alert(response.message || "Issue request sent to the administrator.");
        if (input) input.value = "";
    }
    catch (error) { showApiError(error); }
}

async function returnBook(bookId) {
    const input = document.getElementById("returnBookId");
    const rawId = bookId === undefined ? input.value.trim() : String(bookId);
    if (!/^[1-9]\d*$/.test(rawId)) return alert("Enter a valid Book ID.");
    try { await updateBookStatus(Number(rawId), "return"); if (input) input.value = ""; }
    catch (error) { showApiError(error); }
}

async function logout() {
    try {
        if (authToken()) await apiRequest("/auth/logout", { method: "POST" });
    } catch (error) {
        console.warn("Logout request failed", error);
    } finally {
        clearAuth();
        window.location.href = "index.html";
    }
}

function enforceDashboardAccess() {
    const isDashboard = document.getElementById("dashboard") !== null;
    const isUserDashboard = document.getElementById("userDashboard") !== null;
    if (!authToken()) {
        window.location.href = "index.html";
    } else if (isDashboard && localStorage.getItem("userRole") !== "ADMIN") {
        window.location.href = "user-dashboard.html";
    } else if (isUserDashboard && localStorage.getItem("userRole") === "ADMIN") {
        window.location.href = "dashboard.html";
    }
}

document.addEventListener("DOMContentLoaded", function() {
    initializeAuthentication();
    if (document.getElementById("dashboard") || document.getElementById("userDashboard")) {
        enforceDashboardAccess();
        if (authToken()) loadLibraryData();
    }
});
