<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'website_security');
define('DB_USER', 'root');
define('DB_PASS', '');

// Create database connection
try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch(PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    $pdo = null;
}

// Start session
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 0);
ini_set('session.use_strict_mode', 1);
session_start();

// Security Class (Simplified for login page)
class LoginSecurity {
    private $db;
    private $max_login_attempts = 5;
    private $lockout_time = 900;

    public function __construct($db) {
        $this->db = $db;
    }

    public function sanitizeInput($input) {
        if (is_array($input)) {
            return array_map([$this, 'sanitizeInput'], $input);
        }
        $input = trim($input);
        $input = stripslashes($input);
        $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        return $input;
    }

    public function checkLoginAttempts($ip = null) {
        if (!$this->db) return true;
        $ip = $ip ?: $this->getClientIP();
        
        $stmt = $this->db->prepare("SELECT attempts, locked_until FROM login_attempts WHERE ip_address = ?");
        $stmt->execute([$ip]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            if ($result['locked_until'] && strtotime($result['locked_until']) > time()) {
                return false;
            }
            if ($result['attempts'] >= $this->max_login_attempts) {
                return false;
            }
        }
        return true;
    }

    public function recordFailedAttempt($ip = null) {
        if (!$this->db) return;
        $ip = $ip ?: $this->getClientIP();
        
        $stmt = $this->db->prepare("INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, 1, NOW()) ON DUPLICATE KEY UPDATE attempts = attempts + 1, last_attempt = NOW()");
        $stmt->execute([$ip]);
    }

    public function resetLoginAttempts($ip = null) {
        if (!$this->db) return;
        $ip = $ip ?: $this->getClientIP();
        $stmt = $this->db->prepare("DELETE FROM login_attempts WHERE ip_address = ?");
        $stmt->execute([$ip]);
    }

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
}

// Initialize security
$security = new LoginSecurity($pdo);
$error = '';

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $security->sanitizeInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    // Check login attempts
    if (!$security->checkLoginAttempts()) {
        $error = "Too many failed attempts. Please try again in 15 minutes.";
    } else {
        // Admin credentials
        $admin_email = 'admin@fruitinfo.com';
        $admin_password = 'admin123';
        
        if ($email === $admin_email && $password === $admin_password) {
            $security->resetLoginAttempts();
            $_SESSION['admin_logged_in'] = true;
            $_SESSION['admin_email'] = $email;
            $_SESSION['login_time'] = time();
            
            // Redirect to main website
            header("Location: index.php");
            exit;
        } else {
            $security->recordFailedAttempt();
            $error = "Invalid admin credentials.";
        }
    }
}

// If already logged in, redirect to main site
if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
    header("Location: index.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - FruitInfo</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            background: linear-gradient(135deg, #0c0f0a 0%, #1a1f1c 100%);
            font-family: 'Inter', sans-serif;
        }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="bg-[#1a1f1c] border border-[#800020] rounded-xl p-8 w-full max-w-md shadow-2xl">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-white mb-2">Fruit<span class="text-[#800020]">Info</span></h1>
            <p class="text-gray-400">Admin Access Required</p>
        </div>
        
        <?php if ($error): ?>
            <div class="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded-lg mb-6">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>
        
        <form method="POST" class="space-y-6">
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Admin Email</label>
                <input type="email" name="email" required 
                       class="w-full bg-[#2a302c] border border-[#3a403c] rounded-lg px-4 py-3 text-white focus:outline-none focus:border-[#800020] transition-colors"
                       placeholder="Enter admin email">
            </div>
            
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">Password</label>
                <input type="password" name="password" required 
                       class="w-full bg-[#2a302c] border border-[#3a403c] rounded-lg px-4 py-3 text-white focus:outline-none focus:border-[#800020] transition-colors"
                       placeholder="Enter admin password">
            </div>
            
            <button type="submit" 
                    class="w-full bg-[#800020] hover:bg-[#600015] text-white py-3 px-4 rounded-lg transition-all duration-300 font-semibold text-lg shadow-lg hover:shadow-xl transform hover:-translate-y-1">
                Login to Admin Panel
            </button>
        </form>
        
    </div>
</body>
</html>