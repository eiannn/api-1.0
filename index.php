<?php
// SECURITY CHECK - REQUIRE ADMIN LOGIN
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

// Check if admin is logged in, if not redirect to login
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header("Location: admin-login.php");
    exit;
}

// Check session timeout (30 minutes)
if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > 1800) {
    session_unset();
    session_destroy();
    header("Location: admin-login.php");
    exit;
}

// Update last activity
$_SESSION['last_activity'] = time();

// Security Class for Main Site
class AdvancedSecurity {
    private $db;

    public function __construct($db) {
        $this->db = $db;
        $this->initSecurityHeaders();
    }

    private function initSecurityHeaders() {
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
        header("X-Content-Type-Options: nosniff");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        header("Content-Security-Policy: default-src 'self' https://cdn.tailwindcss.com https://fonts.googleapis.com https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;");
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

    public function logSecurityEvent($ip, $action, $details = "") {
        if (!$this->db) return;
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $stmt = $this->db->prepare("INSERT INTO security_logs (ip_address, user_agent, action, details) VALUES (?, ?, ?, ?)");
        $stmt->execute([$ip, $user_agent, $action, $details]);
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
$security = new AdvancedSecurity($pdo);

// Handle logout
if (isset($_GET['logout'])) {
    $security->logSecurityEvent($security->getClientIP(), "ADMIN_LOGOUT", "User: " . $_SESSION['admin_email']);
    session_unset();
    session_destroy();
    header("Location: admin-login.php");
    exit;
}

// YOUR ORIGINAL FRUIT INFO CODE STARTS HERE
// Initialize variables
$pageTitle = "All Fruits";
$searchQuery = "";
$fruits = [];
$error = null;
$selectedFruit = $_GET['fruit'] ?? '';
$showOnlySelected = isset($_GET['showOnly']);

// Function to fetch all fruits from API
function fetchAllFruits() {
    $url = "https://www.fruityvice.com/api/fruit/all";
    
    // Initialize cURL session
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_USERAGENT, 'FruitInfo Website');
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    if ($response === false) {
        throw new Exception("Failed to connect to API: " . $curlError);
    }
    
    if ($httpCode !== 200) {
        throw new Exception("API returned HTTP $httpCode - Service may be unavailable");
    }
    
    $data = json_decode($response, true);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Invalid JSON response from API");
    }
    
    if (empty($data)) {
        throw new Exception("API returned empty data");
    }
    
    return $data;
}

// Function to get fruit color based on name
function getFruitColor($fruitName) {
    $fruitColors = [
        // Red Fruits
        'apple' => ['primary' => '#dc2626', 'secondary' => '#fecaca', 'accent' => '#ef4444'],
        'strawberry' => ['primary' => '#dc2626', 'secondary' => '#fecaca', 'accent' => '#ef4444'],
        'cherry' => ['primary' => '#dc2626', 'secondary' => '#fecaca', 'accent' => '#ef4444'],
        'raspberry' => ['primary' => '#dc2626', 'secondary' => '#fecaca', 'accent' => '#ef4444'],
        'watermelon' => ['primary' => '#dc2626', 'secondary' => '#bbf7d0', 'accent' => '#22c55e'],
        'pomegranate' => ['primary' => '#dc2626', 'secondary' => '#fecaca', 'accent' => '#ef4444'],
        
        // Orange Fruits
        'orange' => ['primary' => '#ea580c', 'secondary' => '#fed7aa', 'accent' => '#f97316'],
        'mandarin' => ['primary' => '#ea580c', 'secondary' => '#fed7aa', 'accent' => '#f97316'],
        'tangerine' => ['primary' => '#ea580c', 'secondary' => '#fed7aa', 'accent' => '#f97316'],
        'clementine' => ['primary' => '#ea580c', 'secondary' => '#fed7aa', 'accent' => '#f97316'],
        'apricot' => ['primary' => '#fdba74', 'secondary' => '#fed7aa', 'accent' => '#fb923c'],
        'mango' => ['primary' => '#f59e0b', 'secondary' => '#fef3c7', 'accent' => '#d97706'],
        
        // Yellow Fruits
        'banana' => ['primary' => '#eab308', 'secondary' => '#fef9c3', 'accent' => '#ca8a04'],
        'lemon' => ['primary' => '#eab308', 'secondary' => '#fef9c3', 'accent' => '#ca8a04'],
        'pineapple' => ['primary' => '#eab308', 'secondary' => '#fef9c3', 'accent' => '#ca8a04'],
        'passionfruit' => ['primary' => '#eab308', 'secondary' => '#fde047', 'accent' => '#ca8a04'],
        
        // Green Fruits
        'kiwi' => ['primary' => '#16a34a', 'secondary' => '#bbf7d0', 'accent' => '#22c55e'],
        'lime' => ['primary' => '#84cc16', 'secondary' => '#d9f99d', 'accent' => '#65a30d'],
        'avocado' => ['primary' => '#15803d', 'secondary' => '#bbf7d0', 'accent' => '#16a34a'],
        'green apple' => ['primary' => '#84cc16', 'secondary' => '#d9f99d', 'accent' => '#65a30d'],
        'pear' => ['primary' => '#84cc16', 'secondary' => '#d9f99d', 'accent' => '#65a30d'],
        'grape' => ['primary' => '#84cc16', 'secondary' => '#d9f99d', 'accent' => '#65a30d'],
        
        // Purple/Blue Fruits
        'blueberry' => ['primary' => '#7e22ce', 'secondary' => '#e9d5ff', 'accent' => '#a855f7'],
        'plum' => ['primary' => '#7e22ce', 'secondary' => '#e9d5ff', 'accent' => '#a855f7'],
        'grape' => ['primary' => '#7e22ce', 'secondary' => '#e9d5ff', 'accent' => '#a855f7'],
        'fig' => ['primary' => '#7e22ce', 'secondary' => '#e9d5ff', 'accent' => '#a855f7'],
        'blackberry' => ['primary' => '#7e22ce', 'secondary' => '#e9d5ff', 'accent' => '#a855f7'],
        
        // Brown/Tan Fruits
        'coconut' => ['primary' => '#a16207', 'secondary' => '#fef3c7', 'accent' => '#d97706'],
        'date' => ['primary' => '#a16207', 'secondary' => '#fef3c7', 'accent' => '#d97706'],
        
        // Pink Fruits
        'dragonfruit' => ['primary' => '#ec4899', 'secondary' => '#fce7f3', 'accent' => '#f472b6'],
        'guava' => ['primary' => '#ec4899', 'secondary' => '#fce7f3', 'accent' => '#f472b6'],
        'peach' => ['primary' => '#fdba74', 'secondary' => '#fed7aa', 'accent' => '#fb923c'],
    ];
    
    $name = strtolower($fruitName);
    
    // Check for exact matches first
    if (isset($fruitColors[$name])) {
        return $fruitColors[$name];
    }
    
    // Check for partial matches
    foreach ($fruitColors as $key => $colors) {
        if (strpos($name, $key) !== false) {
            return $colors;
        }
    }
    
    // Default colors for unknown fruits
    return ['primary' => '#800020', 'secondary' => '#1a1f1c', 'accent' => '#e8e8e8'];
}

// Get category and search parameters
$category = $_GET['category'] ?? 'all';
$searchQuery = $_GET['search'] ?? '';

// Fetch data based on parameters
try {
    $allFruits = fetchAllFruits();
    
    // Apply filtering based on category and search
    if (!empty($searchQuery)) {
        // Search functionality
        $fruits = array_filter($allFruits, function($fruit) use ($searchQuery) {
            return stripos($fruit['name'], $searchQuery) !== false;
        });
        $fruits = array_values($fruits);
        $pageTitle = "Search Results for: " . htmlspecialchars($searchQuery);
    } else {
        // Category filtering based on actual API data
        switch($category) {
            case 'berries':
                $fruits = array_filter($allFruits, function($fruit) {
                    $berryNames = ['strawberry', 'blueberry', 'raspberry', 'blackberry', 'cranberry', 'boysenberry'];
                    $berryKeywords = ['berry'];
                    $name = strtolower($fruit['name']);
                    
                    foreach ($berryKeywords as $keyword) {
                        if (strpos($name, $keyword) !== false) {
                            return true;
                        }
                    }
                    return in_array($name, $berryNames);
                });
                $pageTitle = "Berries";
                break;
                
            case 'citrus':
                $fruits = array_filter($allFruits, function($fruit) {
                    $citrusNames = ['orange', 'lemon', 'lime', 'grapefruit', 'mandarin', 'tangerine', 'clementine', 'pomelo'];
                    $name = strtolower($fruit['name']);
                    $family = strtolower($fruit['family'] ?? '');
                    $genus = strtolower($fruit['genus'] ?? '');
                    
                    return in_array($name, $citrusNames) || 
                           strpos($family, 'rutaceae') !== false ||
                           strpos($genus, 'citrus') !== false;
                });
                $pageTitle = "Citrus Fruits";
                break;
                
            case 'tropical':
                $fruits = array_filter($allFruits, function($fruit) {
                    $tropicalNames = ['banana', 'pineapple', 'mango', 'papaya', 'coconut', 'avocado', 'guava', 'passion fruit', 'dragon fruit', 'lychee'];
                    $name = strtolower($fruit['name']);
                    return in_array($name, $tropicalNames);
                });
                $pageTitle = "Tropical Fruits";
                break;
                
            case 'stone':
                $fruits = array_filter($allFruits, function($fruit) {
                    $stoneNames = ['peach', 'plum', 'cherry', 'apricot', 'nectarine'];
                    $name = strtolower($fruit['name']);
                    $genus = strtolower($fruit['genus'] ?? '');
                    
                    return in_array($name, $stoneNames) || strpos($genus, 'prunus') !== false;
                });
                $pageTitle = "Stone Fruits";
                break;
                
            case 'melons':
                $fruits = array_filter($allFruits, function($fruit) {
                    $melonNames = ['watermelon', 'melon', 'cantaloupe', 'honeydew'];
                    $name = strtolower($fruit['name']);
                    $family = strtolower($fruit['family'] ?? '');
                    
                    foreach ($melonNames as $melon) {
                        if (strpos($name, $melon) !== false) {
                            return true;
                        }
                    }
                    return strpos($family, 'cucurbitaceae') !== false;
                });
                $pageTitle = "Melons";
                break;
                
            default:
                // All fruits
                $fruits = $allFruits;
                $pageTitle = "All Fruits";
                break;
        }
        
        $fruits = array_values($fruits);
    }
    
    // Sort fruits alphabetically
    if (is_array($fruits)) {
        usort($fruits, function($a, $b) {
            return strcmp($a['name'], $b['name']);
        });
    }
    
} catch (Exception $e) {
    $error = "Unable to load fruit data from API: " . $e->getMessage();
    $fruits = [];
}

// If showOnlySelected is true and we have a selected fruit, filter the fruits array
if ($showOnlySelected && !empty($selectedFruit) && is_array($fruits)) {
    $filteredFruits = [];
    foreach($fruits as $fruit) {
        if ($fruit['name'] === $selectedFruit) {
            $filteredFruits[] = $fruit;
            break;
        }
    }
    $fruits = $filteredFruits;
    if (!empty($fruits)) {
        $pageTitle = htmlspecialchars($selectedFruit);
    }
}

// Handle empty results
if (empty($fruits) && !empty($searchQuery)) {
    $error = "No fruits found matching '" . htmlspecialchars($searchQuery) . "'";
} elseif (empty($fruits) && $category !== 'all') {
    $error = "No " . htmlspecialchars($category) . " fruits found in the database";
} elseif (empty($fruits)) {
    $error = "No fruits available in the database";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FruitInfo - <?php echo $pageTitle; ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Your original CSS styles here */
        body {
            font-family: 'Inter', sans-serif;
            background-color: #0c0f0a;
        }

        .nav-btn {
            display: inline-block;
            background-color: #800020;
            color: #e8e8e8;
            font-weight: 500;
            padding: 0.5rem 1rem;
            border-radius: 0.75rem;
            transition: all 0.3s ease;
            text-decoration: none;
            text-align: center;
            min-width: 100px;
            border: 1px solid #a00030;
            box-shadow: 0 2px 4px rgba(128, 0, 32, 0.3);
        }

        .nav-btn:hover {
            background-color: #600015;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(128, 0, 32, 0.4);
        }

        .nav-btn.active {
            background-color: #600015;
            box-shadow: 0 0 0 2px rgba(232, 232, 232, 0.5);
            border-color: #e8e8e8;
        }

        .fruit-card {
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            border: 2px solid #2a302c;
            opacity: 0;
            transform: translateY(30px) scale(0.95);
            background: linear-gradient(145deg, #1a1f1c 0%, #212624 100%);
            cursor: pointer;
            border-radius: 20px;
            overflow: hidden;
            position: relative;
            backdrop-filter: blur(10px);
        }

        .fruit-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #800020, #e8e8e8, #800020);
            background-size: 200% 100%;
            animation: shimmer 3s ease-in-out infinite;
        }

        @keyframes shimmer {
            0%, 100% { background-position: -200% 0; }
            50% { background-position: 200% 0; }
        }

        .fruit-card.visible {
            opacity: 1;
            transform: translateY(0) scale(1);
        }

        .fruit-card:hover {
            border-color: #800020;
            transform: translateY(-8px) scale(1.02);
            box-shadow: 
                0 20px 40px rgba(128, 0, 32, 0.2),
                0 8px 24px rgba(0, 0, 0, 0.3),
                inset 0 1px 0 rgba(232, 232, 232, 0.1);
        }

        .fruit-card.selected {
            border-color: #e8e8e8;
            box-shadow: 
                0 25px 50px rgba(232, 232, 232, 0.15),
                0 15px 35px rgba(0, 0, 0, 0.4),
                inset 0 2px 0 rgba(232, 232, 232, 0.2);
            transform: scale(1.03);
        }

        .grid-view {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .single-fruit-view {
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 70vh;
            padding: 3rem 0;
        }

        .single-fruit-card {
            max-width: 650px !important;
            width: 100% !important;
            transform: scale(1.08) !important;
            margin: 0 auto !important;
            padding: 2.5rem !important;
            border-width: 3px !important;
            background: linear-gradient(145deg, #1a1f1c 0%, #232826 50%, #1a1f1c 100%) !important;
        }

        .scroll-progress {
            position: fixed;
            top: 0;
            left: 0;
            width: 0%;
            height: 3px;
            background: linear-gradient(90deg, #800020, #e8e8e8, #800020);
            z-index: 1000;
            transition: width 0.3s ease;
        }

        .back-to-top {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: linear-gradient(135deg, #800020 0%, #600015 100%);
            color: #e8e8e8;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.3s ease;
            z-index: 99;
            box-shadow: 0 8px 24px rgba(128, 0, 32, 0.4);
            border: 1px solid #a00030;
        }

        .back-to-top.visible {
            opacity: 1;
            transform: translateY(0);
        }

        .back-to-top:hover {
            background: linear-gradient(135deg, #600015 0%, #400010 100%);
            transform: translateY(-5px) scale(1.1);
            box-shadow: 0 12px 32px rgba(128, 0, 32, 0.5);
        }

        #navMenu.mobile-open {
            display: flex !important;
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #800020 0%, #600015 100%);
            border-top: 1px solid #a00030;
            padding: 1rem;
            flex-direction: column;
            gap: 0.5rem;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        }
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="bg-[#0c0f0a] text-[#e8e8e8] font-inter">
    <!-- Scroll Progress Bar -->
    <div class="scroll-progress"></div>

    <!-- Navigation -->
    <nav class="bg-[#800020] border-b border-[#a00030] sticky top-0 z-50 transition-all duration-300 shadow-lg">
        <div class="container mx-auto px-4 py-3">
            <div class="flex flex-col md:flex-row justify-between items-center">
                <div class="flex items-center justify-between w-full md:w-auto">
                    <div class="flex items-center">
                        <h1 class="text-2xl font-bold text-white">Fruit<span class="text-[#e8e8e8]">Info</span></h1>
                        <span class="ml-3 bg-green-600 text-white px-2 py-1 rounded text-sm">Admin</span>
                    </div>
                    
                    <!-- Mobile Menu Button -->
                    <button id="mobileMenuButton" class="md:hidden text-white p-2 rounded-lg hover:bg-[#600015] transition-colors">
                        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                        </svg>
                    </button>
                </div>
                
                <!-- Search Bar -->
                <div class="w-full md:w-1/3 my-4 md:my-0">
                    <form id="searchForm" class="relative">
                        <input 
                            type="text" 
                            id="searchInput" 
                            name="search" 
                            placeholder="Search fruits..." 
                            class="w-full bg-[#600015] text-white rounded-lg py-2 px-4 focus:outline-none focus:ring-2 focus:ring-[#e8e8e8] border border-[#a00030] placeholder-gray-300"
                            value="<?php echo htmlspecialchars($searchQuery); ?>"
                        >
                        <button type="submit" class="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-300 hover:text-white">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                            </svg>
                        </button>
                    </form>
                </div>
                
                <!-- Category Navigation + Logout -->
                <div id="navMenu" class="hidden md:flex flex-wrap justify-center gap-2 w-full md:w-auto">
                    <a href="?category=all" class="nav-btn <?php echo $category == 'all' && empty($searchQuery) && empty($selectedFruit) ? 'active' : ''; ?>">All Fruits</a>
                    <a href="?category=berries" class="nav-btn <?php echo $category == 'berries' ? 'active' : ''; ?>">Berries</a>
                    <a href="?category=citrus" class="nav-btn <?php echo $category == 'citrus' ? 'active' : ''; ?>">Citrus</a>
                    <a href="?category=tropical" class="nav-btn <?php echo $category == 'tropical' ? 'active' : ''; ?>">Tropical</a>
                    <a href="?category=stone" class="nav-btn <?php echo $category == 'stone' ? 'active' : ''; ?>">Stone Fruits</a>
                    <a href="?category=melons" class="nav-btn <?php echo $category == 'melons' ? 'active' : ''; ?>">Melons</a>
                    
                    <!-- Admin Info & Logout -->
                    <div class="flex items-center gap-2">
                        <span class="text-white text-sm">Welcome, Admin</span>
                        <a href="?logout=true" class="nav-btn bg-red-600 hover:bg-red-700 border-red-500 text-sm">
                            Logout
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <!-- Rest of your original HTML content remains exactly the same -->
    <!-- Main Content -->
    <main class="container mx-auto px-4 py-8 min-h-screen">
        <!-- Page Title and Actions -->
        <div class="mb-8">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-6">
                <div class="flex-1">
                    <h2 class="text-3xl font-bold text-[#e8e8e8] mb-2"><?php echo $pageTitle; ?></h2>
                    <p class="text-gray-400">
                        <?php if ($showOnlySelected && !empty($selectedFruit)): ?>
                            ✨ Viewing <?php echo htmlspecialchars($selectedFruit); ?> in detail
                        <?php else: ?>
                            👆 Click any fruit to view it in detail
                        <?php endif; ?>
                    </p>
                </div>
                
                <!-- Action Buttons -->
                <div class="flex flex-wrap gap-3 mt-4 md:mt-0">
                    <?php if ($showOnlySelected && !empty($selectedFruit)): ?>
                        <button onclick="showAllFruits()" class="bg-[#800020] hover:bg-[#600015] text-white py-3 px-6 rounded-lg transition-all duration-300 font-medium flex items-center text-base">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                            </svg>
                            View All Fruits
                        </button>
                    <?php endif; ?>
                    
                    <?php if (isset($fruits) && is_array($fruits) && !empty($fruits) && !$error && !$showOnlySelected): ?>
                        <div class="bg-[#1a1f1c] rounded-lg px-4 py-2 border border-[#2a302c]">
                            <span class="text-sm text-gray-300">Showing </span>
                            <span class="text-[#e8e8e8] font-semibold"><?php echo count($fruits); ?></span>
                            <span class="text-sm text-gray-300"> fruits</span>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Error Message (if any) -->
        <?php if (isset($error)): ?>
            <div class="bg-yellow-900/30 border border-yellow-700 text-white px-4 py-6 rounded-lg mb-6 text-center">
                <div class="flex items-center justify-center mb-3">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-8 w-8 mr-2 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                    <span class="text-lg"><?php echo htmlspecialchars($error); ?></span>
                </div>
                <div class="mt-4">
                    <a href="?category=all" class="bg-[#800020] hover:bg-[#600015] text-white py-2 px-6 rounded-lg transition-colors inline-block">
                        View All Fruits
                    </a>
                </div>
                <div class="mt-3 text-sm text-gray-300">
                    <p>Data from <a href="https://fruityvice.com" class="text-[#e8e8e8] underline" target="_blank">FruityVice API</a></p>
                </div>
            </div>
        <?php endif; ?>

        <!-- Loading State -->
        <div id="loading" class="hidden flex justify-center items-center py-12">
            <div class="text-center">
                <div class="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-[#e8e8e8] mx-auto mb-4"></div>
                <p class="text-gray-400">Loading fresh fruit data from API...</p>
            </div>
        </div>

        <!-- Fruit Grid -->
        <div id="fruitGrid" class="<?php echo $showOnlySelected && !empty($selectedFruit) ? 'single-fruit-view' : 'grid-view'; ?>">
            <?php if (isset($fruits) && is_array($fruits) && !empty($fruits)): ?>
                <?php foreach($fruits as $index => $fruit): ?>
                    <?php
                    $isSelected = $selectedFruit === $fruit['name'];
                    $fruitColors = getFruitColor($fruit['name']);
                    $cardClass = $isSelected ? 'fruit-card selected cursor-pointer' : 'fruit-card cursor-pointer';
                    $displayClass = $showOnlySelected && !$isSelected ? 'hidden' : '';
                    
                    // Add special class for single fruit view
                    if ($showOnlySelected && $isSelected) {
                        $cardClass .= ' single-fruit-card';
                    }
                    ?>
                    <div class="<?php echo $cardClass . ' ' . $displayClass; ?> fruit-grid-item rounded-xl overflow-hidden shadow-lg transition-all duration-300 hover:shadow-xl hover:-translate-y-2 border-2 <?php echo $isSelected ? 'border-[#e8e8e8] shadow-2xl' : 'border-opacity-30'; ?>"
                         data-fruit-name="<?php echo htmlspecialchars($fruit['name']); ?>"
                         data-fruit-color="<?php echo $fruitColors['primary']; ?>"
                         style="
                             background: linear-gradient(145deg, <?php echo $fruitColors['primary']; ?>15 0%, <?php echo $fruitColors['secondary']; ?>05 100%);
                             border-color: <?php echo $fruitColors['primary']; ?>50;
                         "
                         onclick="selectFruit('<?php echo htmlspecialchars($fruit['name']); ?>')">
                        <div class="p-5">
                            <!-- Fruit Header -->
                            <div class="flex justify-between items-start mb-4">
                                <h3 class="<?php echo $showOnlySelected && $isSelected ? 'text-3xl' : 'text-xl'; ?> font-semibold fruit-name"
                                    style="color: <?php echo $fruitColors['accent']; ?>">
                                    <?php echo htmlspecialchars($fruit['name']); ?>
                                </h3>
                                <span class="text-white text-xs font-medium px-2 py-1 rounded-full shadow-lg"
                                      style="background: <?php echo $fruitColors['primary']; ?>; border: 1px solid <?php echo $fruitColors['primary']; ?>70;">
                                    <?php echo isset($fruit['family']) ? htmlspecialchars($fruit['family']) : 'Fruit'; ?>
                                </span>
                            </div>
                            
                            <div class="space-y-3">
                                <!-- Nutrition Information -->
                                <div class="rounded-lg p-3 border"
                                     style="background: <?php echo $fruitColors['primary']; ?>10; border-color: <?php echo $fruitColors['primary']; ?>30;">
                                    <h4 class="<?php echo $showOnlySelected && $isSelected ? 'text-lg' : 'text-sm'; ?> font-medium mb-2 flex items-center"
                                        style="color: <?php echo $fruitColors['accent']; ?>">
                                        <svg xmlns="http://www.w3.org/2000/svg" class="<?php echo $showOnlySelected && $isSelected ? 'h-5 w-5' : 'h-4 w-4'; ?> mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"
                                             style="color: <?php echo $fruitColors['primary']; ?>">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                        Nutrition (per 100g)
                                    </h4>
                                    <div class="grid grid-cols-2 gap-2 <?php echo $showOnlySelected && $isSelected ? 'text-base' : 'text-sm'; ?>">
                                        <div class="flex justify-between">
                                            <span class="text-opacity-80" style="color: <?php echo $fruitColors['accent']; ?>">Calories:</span>
                                            <span class="font-medium" style="color: <?php echo $fruitColors['accent']; ?>">
                                                <?php echo isset($fruit['nutritions']['calories']) ? htmlspecialchars($fruit['nutritions']['calories']) : 'N/A'; ?>
                                            </span>
                                        </div>
                                        <div class="flex justify-between">
                                            <span class="text-opacity-80" style="color: <?php echo $fruitColors['accent']; ?>">Sugar:</span>
                                            <span class="font-medium" style="color: <?php echo $fruitColors['accent']; ?>">
                                                <?php echo isset($fruit['nutritions']['sugar']) ? htmlspecialchars($fruit['nutritions']['sugar']) . 'g' : 'N/A'; ?>
                                            </span>
                                        </div>
                                        <div class="flex justify-between">
                                            <span class="text-opacity-80" style="color: <?php echo $fruitColors['accent']; ?>">Carbs:</span>
                                            <span class="font-medium" style="color: <?php echo $fruitColors['accent']; ?>">
                                                <?php echo isset($fruit['nutritions']['carbohydrates']) ? htmlspecialchars($fruit['nutritions']['carbohydrates']) . 'g' : 'N/A'; ?>
                                            </span>
                                        </div>
                                        <div class="flex justify-between">
                                            <span class="text-opacity-80" style="color: <?php echo $fruitColors['accent']; ?>">Protein:</span>
                                            <span class="font-medium" style="color: <?php echo $fruitColors['accent']; ?>">
                                                <?php echo isset($fruit['nutritions']['protein']) ? htmlspecialchars($fruit['nutritions']['protein']) . 'g' : 'N/A'; ?>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Additional Info -->
                                <div class="flex justify-between <?php echo $showOnlySelected && $isSelected ? 'text-base' : 'text-sm'; ?>">
                                    <div class="flex items-center">
                                        <span class="text-opacity-80 mr-1" style="color: <?php echo $fruitColors['accent']; ?>">Order:</span>
                                        <span style="color: <?php echo $fruitColors['accent']; ?>"><?php echo isset($fruit['order']) ? htmlspecialchars($fruit['order']) : 'N/A'; ?></span>
                                    </div>
                                    <div class="flex items-center">
                                        <span class="text-opacity-80 mr-1" style="color: <?php echo $fruitColors['accent']; ?>">Genus:</span>
                                        <span style="color: <?php echo $fruitColors['accent']; ?>"><?php echo isset($fruit['genus']) ? htmlspecialchars($fruit['genus']) : 'N/A'; ?></span>
                                    </div>
                                </div>
                                
                                <!-- Additional Nutrition Info for Single View -->
                                <?php if ($showOnlySelected && $isSelected && isset($fruit['nutritions'])): ?>
                                    <div class="rounded-lg p-3 mt-4 border"
                                         style="background: <?php echo $fruitColors['primary']; ?>15; border-color: <?php echo $fruitColors['primary']; ?>40;">
                                        <h4 class="text-lg font-medium mb-2 flex items-center"
                                            style="color: <?php echo $fruitColors['accent']; ?>">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"
                                                 style="color: <?php echo $fruitColors['primary']; ?>">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                            </svg>
                                            Complete Nutritional Information
                                        </h4>
                                        <div class="grid grid-cols-2 gap-3 text-base">
                                            <?php foreach($fruit['nutritions'] as $key => $value): ?>
                                                <div class="flex justify-between">
                                                    <span class="text-opacity-80 capitalize" style="color: <?php echo $fruitColors['accent']; ?>"><?php echo htmlspecialchars($key); ?>:</span>
                                                    <span class="font-medium" style="color: <?php echo $fruitColors['accent']; ?>">
                                                        <?php echo htmlspecialchars($value); ?>
                                                        <?php echo in_array($key, ['sugar', 'carbohydrates', 'protein', 'fat']) ? 'g' : ''; ?>
                                                    </span>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                <?php endif; ?>
                                
                                <!-- Click Indicator (only show in grid view) -->
                                <?php if (!$showOnlySelected || !$isSelected): ?>
                                    <div class="pt-2 border-t text-center"
                                         style="border-color: <?php echo $fruitColors['primary']; ?>30;">
                                        <div class="flex items-center justify-center text-xs"
                                             style="color: <?php echo $fruitColors['primary']; ?>">
                                            <svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.828 14.828a4 4 0 01-5.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                            </svg>
                                            Click to view in detail
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php elseif (!isset($error)): ?>
                <!-- Empty State -->
                <div class="col-span-full text-center py-12">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-16 w-16 mx-auto text-gray-500 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="text-xl font-medium text-[#e8e8e8] mb-2">No fruits found</h3>
                    <p class="text-gray-400 mb-4">Try a different search term or browse by category</p>
                    <a href="?category=all" class="nav-btn inline-block">Browse All Fruits</a>
                </div>
            <?php endif; ?>
        </div>
    </main>

    <!-- Footer -->
    <footer class="bg-[#1a1f1c] border-t border-[#2a302c] py-8">
        <div class="container mx-auto px-4">
            <div class="flex flex-col md:flex-row justify-between items-center">
                <div class="mb-4 md:mb-0">
                    <h2 class="text-xl font-bold text-[#e8e8e8]">Fruit<span class="text-[#800020]">Info</span></h2>
                    <p class="text-gray-400 text-sm mt-1">Your comprehensive source for fruit information</p>
                </div>
                <div class="text-gray-400 text-sm">
                    <p>Live data from <a href="https://fruityvice.com" class="text-[#e8e8e8] hover:text-white transition-colors" target="_blank">FruityVice API</a></p>
                </div>
            </div>
        </div>
    </footer>

    <!-- Back to Top Button -->
    <div class="back-to-top">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18" />
        </svg>
    </div>

    <script>
        // Your original JavaScript code here
        document.addEventListener('DOMContentLoaded', function() {
            initApp();
        });

        function initApp() {
            setupEventListeners();
            initScrollAnimations();
            createScrollProgressBar();
            createBackToTopButton();
            checkSelectedFruit();
            initFruitGridAnimations();
        }

        function setupEventListeners() {
            const searchForm = document.getElementById('searchForm');
            if (searchForm) {
                searchForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    const searchInput = document.getElementById('searchInput');
                    const searchValue = searchInput.value.trim();
                    
                    if (searchValue === '') {
                        window.location.href = '?category=all';
                    } else {
                        showLoadingState();
                        this.submit();
                    }
                });
            }
            
            const mobileMenuButton = document.getElementById('mobileMenuButton');
            const navMenu = document.getElementById('navMenu');
            
            if (mobileMenuButton && navMenu) {
                mobileMenuButton.addEventListener('click', function() {
                    navMenu.classList.toggle('mobile-open');
                    navMenu.classList.toggle('hidden');
                    
                    const icon = this.querySelector('svg');
                    if (navMenu.classList.contains('mobile-open')) {
                        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />';
                    } else {
                        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />';
                    }
                });
                
                document.addEventListener('click', function(e) {
                    if (!navMenu.contains(e.target) && !mobileMenuButton.contains(e.target)) {
                        navMenu.classList.remove('mobile-open');
                        navMenu.classList.add('hidden');
                        const icon = mobileMenuButton.querySelector('svg');
                        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />';
                    }
                });
            }
            
            window.addEventListener('scroll', throttle(handleNavbarScroll, 100));
            window.addEventListener('scroll', throttle(updateProgressBar, 10));
        }

        function selectFruit(fruitName) {
            const url = new URL(window.location);
            const currentFruit = url.searchParams.get('fruit');
            const currentShowOnly = url.searchParams.get('showOnly');
            
            if (currentFruit === fruitName && currentShowOnly === 'true') {
                showAllFruits();
            } else {
                url.searchParams.set('fruit', fruitName);
                url.searchParams.set('showOnly', 'true');
                showLoadingState();
                setTimeout(() => {
                    window.location.href = url.toString();
                }, 300);
            }
        }

        function showAllFruits() {
            const url = new URL(window.location);
            url.searchParams.delete('fruit');
            url.searchParams.delete('showOnly');
            showLoadingState();
            setTimeout(() => {
                window.location.href = url.toString();
            }, 300);
        }

        function checkSelectedFruit() {
            const urlParams = new URLSearchParams(window.location.search);
            const selectedFruit = urlParams.get('fruit');
            const showOnly = urlParams.get('showOnly');
            
            if (selectedFruit && showOnly === 'true') {
                setTimeout(() => {
                    const selectedCard = document.querySelector(`[data-fruit-name="${selectedFruit}"]`);
                    if (selectedCard) {
                        selectedCard.scrollIntoView({ 
                            behavior: 'smooth', 
                            block: 'center' 
                        });
                    }
                }, 500);
            }
        }

        function initScrollAnimations() {
            const observerOptions = {
                root: null,
                rootMargin: '0px',
                threshold: 0.1
            };

            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('visible');
                        observer.unobserve(entry.target);
                    }
                });
            }, observerOptions);

            const animatedElements = document.querySelectorAll('.fruit-grid-item');
            animatedElements.forEach(el => {
                observer.observe(el);
            });
        }

        function initFruitGridAnimations() {
            const fruitCards = document.querySelectorAll('.fruit-card');
            fruitCards.forEach((card, index) => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(30px)';
                
                setTimeout(() => {
                    card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }, (index % 8) * 100);
            });
        }

        function createScrollProgressBar() {}

        function updateProgressBar() {
            const progressBar = document.querySelector('.scroll-progress');
            if (!progressBar) return;

            const windowHeight = window.innerHeight;
            const documentHeight = document.documentElement.scrollHeight - windowHeight;
            const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
            
            const scrollPercentage = (scrollTop / documentHeight) * 100;
            progressBar.style.width = `${scrollPercentage}%`;
        }

        function createBackToTopButton() {
            const backToTopBtn = document.querySelector('.back-to-top');
            if (!backToTopBtn) return;

            backToTopBtn.addEventListener('click', scrollToTop);

            window.addEventListener('scroll', throttle(() => {
                const scrolled = window.pageYOffset;
                if (scrolled > 300) {
                    backToTopBtn.classList.add('visible');
                } else {
                    backToTopBtn.classList.remove('visible');
                }
            }, 100));
        }

        function scrollToTop() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        }

        function handleNavbarScroll() {
            const navbar = document.querySelector('nav');
            const scrolled = window.pageYOffset;
            
            if (scrolled > 50) {
                navbar.classList.add('navbar-scrolled');
            } else {
                navbar.classList.remove('navbar-scrolled');
            }
        }

        function throttle(func, limit) {
            let inThrottle;
            return function() {
                const args = arguments;
                const context = this;
                if (!inThrottle) {
                    func.apply(context, args);
                    inThrottle = true;
                    setTimeout(() => inThrottle = false, limit);
                }
            }
        }

        function showLoadingState() {
            const fruitGrid = document.getElementById('fruitGrid');
            const loadingElement = document.getElementById('loading');
            
            if (fruitGrid && loadingElement) {
                fruitGrid.style.opacity = '0.5';
                loadingElement.classList.remove('hidden');
                loadingElement.style.display = 'flex';
            }
        }

        window.selectFruit = selectFruit;
        window.showAllFruits = showAllFruits;
    </script>
</body>
</html>