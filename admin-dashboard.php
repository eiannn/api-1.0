<?php
require_once 'config.php';
require_once 'security.php';

$security = new AdvancedSecurity($pdo);

// Check if user is admin
if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
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

// Get security stats
$stmt = $pdo->query("SELECT COUNT(*) as total_logs FROM security_logs");
$total_logs = $stmt->fetch()['total_logs'];

$stmt = $pdo->query("SELECT COUNT(*) as blocked_ips FROM blocked_ips WHERE blocked_until > NOW() OR blocked_until IS NULL");
$blocked_ips = $stmt->fetch()['blocked_ips'];

$stmt = $pdo->query("SELECT COUNT(*) as recent_attempts FROM login_attempts WHERE last_attempt > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
$recent_attempts = $stmt->fetch()['recent_attempts'];

// Get recent security events
$stmt = $pdo->query("SELECT * FROM security_logs ORDER BY log_time DESC LIMIT 10");
$recent_events = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - FruitInfo</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <nav class="bg-blue-600 text-white p-4">
        <div class="container mx-auto flex justify-between items-center">
            <h1 class="text-xl font-bold">FruitInfo Admin Dashboard</h1>
            <div class="flex items-center space-x-4">
                <span>Welcome, <?php echo htmlspecialchars($_SESSION['user_email']); ?></span>
                <a href="logout.php" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded">Logout</a>
                <a href="index.php" class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded">View Site</a>
            </div>
        </div>
    </nav>

    <div class="container mx-auto p-6">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="text-lg font-semibold mb-2">Total Security Events</h3>
                <p class="text-3xl font-bold text-blue-600"><?php echo $total_logs; ?></p>
            </div>
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="text-lg font-semibold mb-2">Blocked IPs</h3>
                <p class="text-3xl font-bold text-red-600"><?php echo $blocked_ips; ?></p>
            </div>
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="text-lg font-semibold mb-2">Recent Login Attempts</h3>
                <p class="text-3xl font-bold text-orange-600"><?php echo $recent_attempts; ?></p>
            </div>
        </div>

        <div class="bg-white rounded-lg shadow">
            <div class="p-6 border-b">
                <h2 class="text-xl font-semibold">Recent Security Events</h2>
            </div>
            <div class="p-6">
                <div class="overflow-x-auto">
                    <table class="min-w-full">
                        <thead>
                            <tr class="bg-gray-50">
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Address</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            <?php foreach($recent_events as $event): ?>
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo $event['log_time']; ?></td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo $event['ip_address']; ?></td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900"><?php echo $event['action']; ?></td>
                                <td class="px-6 py-4 text-sm text-gray-900"><?php echo $event['details']; ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</body>
</html>