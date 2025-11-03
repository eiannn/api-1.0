<?php
class AdvancedSecurity {
    private $db;
    private $max_login_attempts = 5;
    private $lockout_time = 900; // 15 minutes
    private $block_time = 86400; // 24 hours

    public function __construct($db) {
        $this->db = $db;
        $this->initSecurityHeaders();
    }

    // Initialize security headers
    private function initSecurityHeaders() {
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        header("X-Content-Type-Options: nosniff");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Content-Security-Policy: default-src 'self' https://cdn.tailwindcss.com https://fonts.googleapis.com https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;");
    }

    // Sanitize input data
    public function sanitizeInput($input) {
        if (is_array($input)) {
            return array_map([$this, 'sanitizeInput'], $input);
        }
        
        $input = trim($input);
        $input = stripslashes($input);
        $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        
        return $input;
    }

    // Validate email
    public function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    // Check if IP is blocked
    public function isIPBlocked($ip = null) {
        $ip = $ip ?: $this->getClientIP();
        
        $stmt = $this->db->prepare("SELECT blocked_until FROM blocked_ips WHERE ip_address = ? AND (blocked_until IS NULL OR blocked_until > NOW())");
        $stmt->execute([$ip]);
        
        return $stmt->rowCount() > 0;
    }

    // Check login attempts
    public function checkLoginAttempts($ip = null) {
        $ip = $ip ?: $this->getClientIP();
        
        if ($this->isIPBlocked($ip)) {
            return false;
        }

        $stmt = $this->db->prepare("SELECT attempts, locked_until FROM login_attempts WHERE ip_address = ?");
        $stmt->execute([$ip]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            if ($result['locked_until'] && strtotime($result['locked_until']) > time()) {
                return false;
            }
            
            if ($result['attempts'] >= $this->max_login_attempts) {
                $this->blockIP($ip, "Too many failed login attempts");
                return false;
            }
        }

        return true;
    }

    // Record failed login attempt
    public function recordFailedAttempt($ip = null) {
        $ip = $ip ?: $this->getClientIP();
        
        $stmt = $this->db->prepare("INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, 1, NOW()) 
                                   ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt = NOW()");
        $stmt->execute([$ip]);

        $stmt = $this->db->prepare("SELECT attempts FROM login_attempts WHERE ip_address = ?");
        $stmt->execute([$ip]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result && $result['attempts'] >= $this->max_login_attempts) {
            $lock_until = date('Y-m-d H:i:s', time() + $this->lockout_time);
            $stmt = $this->db->prepare("UPDATE login_attempts SET locked_until = ? WHERE ip_address = ?");
            $stmt->execute([$lock_until, $ip]);
            
            $this->logSecurityEvent($ip, "ACCOUNT_LOCKED", "Too many failed login attempts");
        }
    }

    // Reset login attempts on successful login
    public function resetLoginAttempts($ip = null) {
        $ip = $ip ?: $this->getClientIP();
        
        $stmt = $this->db->prepare("DELETE FROM login_attempts WHERE ip_address = ?");
        $stmt->execute([$ip]);
    }

    // Block IP address
    public function blockIP($ip, $reason = "Security violation") {
        $block_until = date('Y-m-d H:i:s', time() + $this->block_time);
        
        $stmt = $this->db->prepare("INSERT INTO blocked_ips (ip_address, reason, blocked_until) VALUES (?, ?, ?) 
                                   ON DUPLICATE KEY UPDATE reason = ?, blocked_until = ?");
        $stmt->execute([$ip, $reason, $block_until, $reason, $block_until]);
        
        $this->logSecurityEvent($ip, "IP_BLOCKED", $reason);
    }

    // Get client IP
    public function getClientIP() {
        $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return '127.0.0.1';
    }

    // Log security events
    public function logSecurityEvent($ip, $action, $details = "") {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $stmt = $this->db->prepare("INSERT INTO security_logs (ip_address, user_agent, action, details) VALUES (?, ?, ?, ?)");
        $stmt->execute([$ip, $user_agent, $action, $details]);
    }

    // Generate CSRF token
    public function generateCSRFToken() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    // Validate CSRF token
    public function validateCSRFToken($token) {
        if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
            $this->logSecurityEvent($this->getClientIP(), "CSRF_ATTACK", "Invalid CSRF token");
            return false;
        }
        return true;
    }

    // Check if user is admin (for protected areas)
    public function isAdmin() {
        return isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin';
    }

    // Basic security check for all pages
    public function basicSecurityCheck() {
        $ip = $this->getClientIP();
        
        // Log page access
        $this->logSecurityEvent($ip, "PAGE_ACCESS", "Accessed: " . ($_SERVER['REQUEST_URI'] ?? 'unknown'));
        
        // Check if IP is blocked
        if ($this->isIPBlocked($ip)) {
            $this->logSecurityEvent($ip, "BLOCKED_IP_ACCESS", "Blocked IP tried to access site");
            http_response_code(403);
            die("Access denied. Your IP has been blocked for security reasons.");
        }
    }
}
?>